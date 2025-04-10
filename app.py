from flask import Flask, request, session, render_template, redirect, flash, url_for, jsonify
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_cors import CORS
import os, datetime, hashlib, hmac, threading, time, requests, json
from sqlalchemy import func, text
from models import db, Transaction, AuthLog, ClientSession, Subscriber
from tzlocal import get_localzone
from dateutil import parser
import pytz
from api import api_blueprint
from user_agents import parse
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = os.environ.get("APP_SECRET_KEY").encode()
# Import configurations from .env file
# app.config.from_object("config")

timezone = pytz.timezone('Asia/Manila')

TOKEN_SECRET = os.environ.get("TOKEN_SECRET").encode()
STATIC_TOKEN = os.environ.get("STATIC_TOKEN")
FREE_DEFAULT_DATA_LIMIT = int(os.environ.get("FREE_DEFAULT_DATA_LIMIT"))
FREE_DATA_TYPE = os.environ.get("FREE_DATA_TYPE")
FREE_DATA_CD = int(os.environ.get("FREE_DATA_CD"))
PAID_DEFAULT_DATA_LIMIT = int(os.environ.get("PAID_DEFAULT_DATA_LIMIT"))
PAID_DATA_TYPE = os.environ.get("PAID_DATA_TYPE")

ACC_DEVICE_LIMIT = int(os.environ.get("ACC_DEVICE_LIMIT"))
ALLOW_MULTIPLE_DEVICES = int(os.environ.get("ALLOW_MULTIPLE_DEVICES"))

ACCOUNT_NUMBER = "RES-201902-1" # static for testing login with account number, remove before prod

POSTGRES = json.loads(os.environ.get("POSTGRES"))

MYSQL = json.loads(os.environ.get("MYSQL"))

KEYCLOAK_CLIENT= os.environ.get("KEYCLOAK_CLIENT")
KEYCLOAK_SECRET= os.environ.get("KEYCLOAK_SECRET")
TOKEN_URL= os.environ.get("TOKEN_URL")

PORTAL_URL_ROOT = os.environ.get("PORTAL_URL_ROOT")
DEFAULT_URL = os.environ.get("DEFAULT_URL")

KEYCLOAK_SSID = os.environ.get("KEYCLOAK_SSID")

PKG_FREE = os.environ.get("PKG_FREE")
PKG_PAID = os.environ.get("PKG_PAID")
PKG_UNLI = os.environ.get("PKG_UNLI")

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_BINDS'] = {
    'mysql': 'mysql+mysqlconnector://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % MYSQL
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# To import/register the api.py
app.register_blueprint(api_blueprint, url_prefix="/api")

# Generates new token based on secret key and mac address 
def genToken(mac): # generates 1 unique token per mac address
    secret_key = TOKEN_SECRET
    hashed_mac = mac.encode('utf-8')
    hmac_object = hmac.new(secret_key, hashed_mac, hashlib.sha256)
    hmac_hex = hmac_object.hexdigest()[:32]

    app.logger.info('token generated: '+ hmac_hex + ' from mac: '+ mac)

    session['token'] = hmac_hex # uuid.uuid4().hex
    session.modified = True

# Encrypt the password submitted from form
def encryptPass(password):
    return password[::-1]

# For future purposes in setting limitations
def getLimit(gw_id, user_id, type_, default_limit):
    return default_limit

# For checking account status
def checkAccountStatus(account_number):
    
    result = Subscriber.query.filter_by(account_Number=account_number).first()
    
    if result: # If account exists, return the subscriber status, else return "NOT FOUND"
        return result.subscriber_status
    
    return "NOT FOUND"

# <-------------------- ROUTES --------------------->
@app.route('/wifidog/ping', strict_slashes=False)
@app.route('/ping', strict_slashes=False)
def ping():
    app.logger.info(f'{str(request.remote_addr)} accessed /ping with the url: {request.url}')
    return "Pong"

@app.route('/check/<site>', strict_slashes=False)
def check(site):
    response = os.system(f"ping -c 4 {site}")  # -c 4 means sending 4 ping requests
    if response == 0:
        return f"Ping to {site} successful!"
    else:
        return f"Ping to {site} failed."

# <-------------------- ACCOUNT-BASED LOGIN ROUTE --------------------->
@app.route('/wifidog/login/', methods=['GET', 'POST'], strict_slashes=False)
@app.route('/login/', methods=['GET', 'POST'], strict_slashes=False)
def login(): 
    current_time = datetime.datetime.now(timezone)
    current_date = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')

    # For form submission
    if request.method == 'POST':
        # gets parameters from submitted form
        account_number = request.form.get('uname', '').strip()
        # pword = encryptPass(request.form.get('pword'))
        package = request.form.get('package') # either Free or Paid
        token = session['token'] 
        # package = "Paid" ## FOR TESTING PAID DATA, PLEASE REMOVE BEFORE PROD

        # get transaction details via token
        trans = Transaction.query.filter_by(token=token).first() 
        trans.last_active = current_date
        db.session.commit()

        if not account_number or account_number == "None": # for testing login with account number, remove if-block before prod
            app.logger.info('No account number found. Using default account number.')
            account_number = ACCOUNT_NUMBER 

        account_status =  checkAccountStatus(account_number)

        if account_status == "NOT FOUND":
            return render_template('logout.html', message=f"Account {account_number} not found. Please login with a valid credentials to continue.", hideReturnToHome=True)
        
        if package == PKG_PAID and account_status == "NEW":
            return render_template('logout.html', message="New accounts are not eligible for this package. Please upgrade your status to continue.", hideReturnToHome=True)
                
        trans.account_Number = account_number # update acc_id 
        db.session.commit()
        session["uname"] = account_number

        # check if client has associated session
        if ClientSession.query.filter_by(account_Number=account_number, package=package).count() > 0: # if client has session for chosen package
            sesh = ClientSession.query.filter_by(account_Number=account_number, package=package).first() # get details of session
            limit_count = int(sesh.limit_count)
            if sesh.limit_type =="mb":
                limit_count = limit_count * 1000000
            if int(sesh.counter) >= limit_count : # if session's counter reached the limit
                if package == PKG_FREE: # if free session
                    ### FOR TESTING **cooldown is changed to minutes, change to 1 day before moving to prod**
                    if current_time - datetime.datetime.strptime(sesh.last_modified, "%Y-%m-%d %H:%M:%S.%f %z") > datetime.timedelta(minutes=FREE_DATA_CD): # check if cooldown period is over **change it to 24 hours or next day
                        app.logger.info(f'last modified date: {sesh.last_modified}, current time: {current_time}. limit for {trans.mac} has been reset. resetting session')
                        
                        # resets free session details
                        sesh.limit_count = FREE_DEFAULT_DATA_LIMIT
                        sesh.limit_type = FREE_DATA_TYPE
                        sesh.counter = 0
                        sesh.last_modified = current_date
                        trans.package = sesh.package
                        db.session.commit()

                    else: # if free package limit is reached but cooldown period has not elapsed check if paid package exists
                        app.logger.info(f"{trans.mac} reached the free package limit for today. checking if paid package exists")
                        if ClientSession.query.filter_by(account_Number=account_number, package=PKG_PAID).count() > 0: # if client has paid session
                            app.logger.info(f'paid session exists. checking if paid session limit is reached')
                            sesh = ClientSession.query.filter_by(account_Number=account_number, package=PKG_PAID).first() # get session details
                            limit_count = int(sesh.limit_count)
                            if sesh.limit_type =="mb":
                                limit_count = limit_count * 1000000
                            if int(sesh.counter) >= limit_count:
                                app.logger.info(f"{trans.mac} reached the limit for paid session. denying auth")
                                return render_template('logout.html', message="You have already used up all your sessions.", returnLink=url_for('access'), return_text="Back")
                            else: # if paid session can still be used
                                # update transaction and session details
                                trans.package = sesh.package
                                sesh.last_modified = current_date
                                db.session.commit()
                                app.logger.info(f'paid session limit is not reached. using paid session')
                        else: # if client only has free session
                            app.logger.info(f"{trans.mac} used up free session and no paid session found. denying auth")
                            return render_template('logout.html', message="You have already used up your free session for today.", returnLink=url_for('access'), return_text="Back")
                
                else: # if session is paid
                    app.logger.info(f"{trans.mac} reached the limit for paid session. denying auth")
                    return render_template('logout.html', message="You have already used up your session.", returnLink=url_for('access'), return_text="Back")
                
            else: # if session has not hit limit
                sesh.last_modified = current_date
                trans.package = sesh.package
                db.session.commit()
                app.logger.info(f'{trans.mac} currently has an active session. proceeding with auth')

        # if client does not have session created yet, initialize session
        else:
            app.logger.info(f'client has no session associated with the package. creating session details')
            
            limit_count = FREE_DEFAULT_DATA_LIMIT
            limit_type = FREE_DATA_TYPE
            if package == PKG_PAID:
                limit_count = PAID_DEFAULT_DATA_LIMIT
                limit_type = PAID_DATA_TYPE
                
            new_session = ClientSession(account_Number=account_number, package=package, limit_count=limit_count, limit_type=limit_type, counter=0, incoming_packets= 0, outgoing_packets=0, created_on=current_time, last_modified=current_date) 
            db.session.add(new_session)
            db.session.commit() 

            trans.package = new_session.package
            db.session.commit() 
        
        # updating transaction details
        trans.stage = "authenticated"
        trans.last_active = current_date

        log = AuthLog(account_Number=account_number, mac=trans.mac, gw_id=session['gw_id'], stage="authenticated")
        db.session.add(log)
        db.session.commit()

        session.permanent = True # session persists even after browser closes

        app.logger.info(f'authenticating {trans.mac} with wifidog auth token: http://{trans.gw_address}:{trans.gw_port}/wifidog/auth?token={trans.token}')
        return redirect(f"http://{trans.gw_address}:{trans.gw_port}/wifidog/auth?token={trans.token}", code=302) # client is given internet access 
        
    else: # For GET request, on first connection, captive portal redirects here
        app.logger.info(f'{str(request.remote_addr)} accessed /ping with the url: {request.url}')

        if request.headers.get('isHTTPS') == "no": # if request url is an https request then redirect to portal
            path = str(request.url).replace(str(request.url_root),PORTAL_URL_ROOT,1)
            return render_template('redirect.html', path=path)
        
        # retrieve parameters from url and store the values in session[]
        session['gw_id'] = request.args.get('gw_id', default='', type=str)
        session['gw_sn'] = request.args.get('gw_sn', default='', type=str)
        session['gw_address'] = request.args.get('gw_address', default='', type=str)
        session['gw_port'] = request.args.get('gw_port', default='', type=str)
        session['ip'] = request.args.get('ip', default='', type=str)
        session['mac'] = request.args.get('mac', default='', type=str)
        session['apmac'] = request.args.get('apmac', default='', type=str)
        session['ssid'] = request.args.get('ssid', default='', type=str)
        session['vlanid'] = request.args.get('vlanid', default='', type=str)
        session['token'] = request.cookies.get('token') 
        session['device'] = request.headers.get('User-Agent')
        session['logged_in'] = True
        session.modified = True
        
        # catch errors: if no IP parameter, if not accessed through wifi, redirect
        if session['ip'] == '' or session['ip'] == None:
            return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)

        # 1 transaction = 1 device
        if Transaction.query.filter_by(mac=session['mac'], device=session['device']).count() > 0: # if device exists in transactions, get token and update last active
            session['token'] = Transaction.query.filter_by(mac=session['mac'], device=session['device']).first().token
            app.logger.info(f'found transaction for current client')

        # if token is null, generate token for client
        if session['token'] == None:
            app.logger.info(f'cannot find token for current client. creating new transaction')
            genToken(session['mac'])             
            # create new client transaction
            trans = Transaction(vlanid=session['vlanid'], gw_id=session['gw_id'], gw_sn=session['gw_sn'], gw_address=session['gw_address'], gw_port=session['gw_port'], ssid=session['ssid'], apmac=session['apmac'], mac=session['mac'], device=session['device'], ip=session['ip'], token=session['token'], stage="capture", total_incoming_packets=0, total_outgoing_packets=0, created_on=current_time, last_active=current_date)
            db.session.add(trans)
        else: 
            # if client already has token, update transaction details
            trans = Transaction.query.filter_by(token=session['token']).first()
            trans.gw_sn = session['gw_sn']
            trans.gw_id = session['gw_id']
            trans.ip = session['ip']
            trans.gw_address = session['gw_address']
            trans.gw_port = session['gw_port']
            trans.mac = session['mac']
            trans.apmac = session['apmac']
            trans.ssid = session['ssid']
            trans.vlanid = session['vlanid']
            trans.stage = "capture"
            trans.last_active = current_date
            db.session.commit()
            app.logger.info(f'updating transaction details.')

        log = AuthLog(mac=session['mac'], gw_id=session['gw_id'], stage="capture")
        db.session.add(log)
        db.session.commit()
        app.logger.info('client details captured')

        if KEYCLOAK_SSID in session['ssid']:
            return redirect(url_for('keycloak'))
            # return redirect(url_for('keycloaksite'))
        
        # Fetch recent logins by calling function
        login_history = get_recent_logins(account_number)
        return render_template('index.html', login_history=login_history)
        # return render_template('index.html')
        

# <-------------------- INSTANT ACCESS ROUTE --------------------->
@app.route('/access/')
def access():
    app.logger.info(f'{str(request.remote_addr)} accessed /ping with the url: {request.url}')

    # Check if there is a gateway ID stored in session
    if not session.get('gw_id'):
        flash("Gateway ID is missing.")
        return redirect(url_for('login'))
    
    # Get dynamic data limits, @hardcoded default values
    limit1 = getLimit(session['gw_id'], 1, 'dd', 50000000)/10000000000

    def format_limit(limit):
        if limit >= 1000000:
            return "{0:.0f} TB".format(limit/1000000)
        elif limit >= 1000:
            return "{0:.0f} GB".format(limit/1000)
        else:
            return "{0:.0f} MB".format(limit)
    
    return render_template('access.html', limit1=format_limit(limit1))

# <-------------------- AUTHENTICATION ROUTE --------------------->
@app.route('/wifidog/auth', methods=['GET', 'POST'], strict_slashes=False)
@app.route('/auth', methods=['GET', 'POST'], strict_slashes=False)
def auth():
    app.logger.info(f'{str(request.remote_addr)} accessed /auth with the url: {request.url}')
    # return "Auth: 0" # emergency logout button (uncomment and wait for AP to request to server)

    current_time = datetime.datetime.now(timezone)
    current_date = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
 
    # retrieve parameters from request url
    mac_n = request.args.get('mac', default='', type=str)
    token_n = request.args.get('token', default='', type=str)
    stage_n = request.args.get('stage', default='', type=str)
    incoming_n = request.args.get('incoming', default=0, type=int)
    outgoing_n = request.args.get('outgoing', default=0, type=int)

    # Check if there is a token
    if not token_n:
        app.logger.warning('no token provided')
        return "No authentication token provided.", 403
    
    # Check if stage is given
    if not stage_n:
        app.logger.warning('no stage found')
        return "No stage found.", 403

    if Transaction.query.filter_by(token=token_n).count() == 0:
        app.logger.warning('transaction not found')
        return "No transaction was found.", 403

    trans = Transaction.query.filter_by(token=token_n).first() # get transactions details (1 transaction per device)
    app.logger.info(f'client mac: {mac_n} token_n: {token_n} stage_n: {stage_n} incoming: {incoming_n} outgoing: {outgoing_n}')
    
     # <------ Logouts client ------> # for stage=logout
    if stage_n == "logout": # cuts connection during logout stage and updates database
        app.logger.info(f'reached auth stage=logout checker')
        trans.stage = "logout"

        log = AuthLog(account_Number=trans.account_Number, mac=trans.mac, gw_id=trans.gw_id, stage="logout")
        db.session.add(log)
        db.session.commit()
        app.logger.info(f'{trans.mac} is being logged out')
        return "Auth: 0"

    if trans.stage == "logout": # for when client manually logs out via button
        app.logger.info(f'{trans.mac} has been logged out')
        return "Auth: 0"
    
    # <------ Updates counter ------>  # for stage=counter
    if 'counter' in stage_n.lower(): 
        app.logger.info(f'reached auth stage=counter checker')
        sesh = None # placeholder

        # checks if client has an active unlimited session
        if ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_UNLI).count() > 0: # if client has unlimited session 
            sesh = ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_UNLI).first() # store unlimited session details
            app.logger.info(f'found unlimited session for {trans.mac}. using unlimited session details')

        # checks if client has an active free session
        if sesh is None and ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_FREE).count() > 0: # if client has free session 
            sesh = ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_FREE).first() # store free session details
            app.logger.info(f'found free session for {trans.mac}. using free session details')

            limit_count = int(sesh.limit_count)
            if sesh.limit_type == "mb":
                limit_count = limit_count * 1000000
            if int(sesh.counter) >= limit_count: # if session limit is reached, remove session details
                sesh = None
                app.logger.info(f'free session for {trans.mac} has reached limit.')
        
        if sesh is None and ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_PAID).count() > 0: # if client does not have active free session and if paid session exists
            sesh = ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_PAID).first() # store paid session details
            app.logger.info(f'found paid session for {trans.mac}. using paid session details')

            limit_count = int(sesh.limit_count)
            if sesh.limit_type == "mb":
                limit_count = limit_count * 1000000
            if int(sesh.counter) >= limit_count: # if session limit is reached, remove session details
                sesh = None
                app.logger.info(f'paid session for {trans.mac} has reached limit.')

        if sesh is None: # if client neither has free nor paid sessions
            app.logger.info(f'{trans.mac} does not have any usable session. denying auth')
            return "Auth: 0"
        else: # if at least one usable session exists
            last_counter = int(sesh.counter)
            last_incoming_packets = int(sesh.incoming_packets) # store previous incoming packets for comparison
            last_outgoing_packets = int(sesh.outgoing_packets) # store previous outgoing packets for comparison
            # evaluates packets from auth
            if incoming_n != 0 and outgoing_n != 0: # if both values are not 0, data is being exchanged
                if incoming_n != last_incoming_packets: # if new and old incoming packets are different, record new activity
                    if sesh.package != PKG_UNLI:
                        if sesh.limit_type == "mb":
                            sesh.counter = int(sesh.counter) + ((incoming_n + outgoing_n) - (last_incoming_packets + last_outgoing_packets))
                        elif sesh.limit_type == "min":
                            sesh.counter = int(sesh.counter) + 1
                    sesh.incoming_packets = incoming_n # update new incoming packet
                    sesh.outgoing_packets = outgoing_n # update new outgoing packet
                    db.session.commit()

                    app.logger.info(f'{trans.mac} is using their data. previous packets:{last_incoming_packets} + {last_outgoing_packets} = old octet: {last_incoming_packets+last_outgoing_packets}, new packets:{incoming_n} + {outgoing_n} = new octet: {incoming_n+outgoing_n}, new counter: {sesh.counter}')
                    
                    trans.total_incoming_packets = int(trans.total_incoming_packets) + (incoming_n - last_incoming_packets)
                    trans.total_outgoing_packets = int(trans.total_outgoing_packets) + (outgoing_n - last_outgoing_packets)
                else: # if new incoming and old incoming packets are the same then there is no new activity from client 
                    app.logger.info(f'{trans.mac} is idle')
                    sesh.last_modified=current_date
                    trans.last_active = current_date
                    db.session.commit()
                    return "Auth: 0" # disconnect client if idle
                
            else: # if incoming and outgoing packets are 0 then client has no internet activity
                app.logger.info(f'{trans.mac} has yet to send/receive data')

        trans.last_active = current_date
        sesh.last_modified=current_date
        session['stage'] = stage_n
        db.session.commit()

        if sesh.package == PKG_UNLI:
            return "Auth: 1"
        else:
            limit_count = int(sesh.limit_count)
            if sesh.limit_type == "mb":
                limit_count = limit_count * 1000000
            if int(sesh.counter) >= limit_count: # if session limit is reached check package 
                if sesh.package == PKG_FREE and ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_PAID).count() > 0: # if newly expired session is free and acc id exists
                    sesh = ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_PAID).first()
                    limit_count = int(sesh.limit_count)
                    if sesh.limit_type == "mb":
                        limit_count = limit_count * 1000000
                    if int(sesh.counter) >= limit_count: # if session limit is reached
                        sesh = None
                        app.logger.info(f'{trans.mac} has reached free package limit and has no usable paid package.')
                        return "Auth: 0"
                    else:
                        app.logger.info(f'{trans.mac} still has a usable paid session. allowing auth')
                        return "Auth: 1"
                else:
                    app.logger.info(f'{trans.mac} has reached free package limit and has no usable paid package.')
                    return "Auth: 0"
            else:
                app.logger.info(f'{trans.mac} still has a usable session left. allowing auth')
                return "Auth: 1"
    
    # <------ Logins client ------> # for stage=login
    if stage_n == "login":
        app.logger.info(f'reached auth login checker')
        sesh = None

        # prioritizes the use of unlimited session 
        if ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_UNLI).count() > 0: # if unlimited session exists
            sesh = ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_UNLI).first()
            trans.last_active = current_date
            sesh.last_modified = current_date
            sesh.incoming_packets = 0
            sesh.outgoing_packets = 0
            db.session.commit()
            return "Auth: 1"

        # checks if free session did not hit limit yet
        if ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_FREE).count() > 0: # if free session exists
            sesh = ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_FREE).first() # get free session details
            limit_count = int(sesh.limit_count)
            if sesh.limit_type == "mb":
                limit_count = limit_count * 1000000
            if int(sesh.counter) > limit_count: # if free package has reached limit 
                sesh = None # reset sesh
            
        # checks if paid package exists
        if sesh is None: 
            if ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_PAID).count() > 0: # if paid session exists
                sesh = ClientSession.query.filter_by(account_Number=trans.account_Number, package=PKG_PAID).first() # get paid session details

        if sesh is not None:
            trans.last_active = current_date
            sesh.last_modified = current_date
            db.session.commit()
            
            limit_count = int(sesh.limit_count)
            if sesh.limit_type == "mb":
                limit_count = limit_count * 1000000
            if int(sesh.counter) < limit_count: # if free package has not reached limit 
                app.logger.info(f'{mac_n} has not reached limit for {sesh.package.lower()} package. authenticating client')
                sesh.incoming_packets = 0
                sesh.outgoing_packets = 0
                db.session.commit()
                return "Auth: 1"
        
    app.logger.warning('reached the end of /auth. denying auth ')
    return "Auth: 0"


# <-------------------- DATA ADJUSTMENT ROUTE --------------------->
@app.route('/data-inquiry', strict_slashes=False)
def inquire(): 
    app.logger.info(f'{str(request.remote_addr)} accessed /ping with the url: {request.url}')

    account_Number = request.args.get('acc_num', default='', type=str)

    if account_Number == '':
        app.logger.warning('incomplete parameters given')
        return "The request was invalid and cannot be processed.", 400

    if Transaction.query.filter_by(account_Number=account_Number).count() > 0:
        trans = Transaction.query.filter_by(account_Number=account_Number).first()
        free_sesh = None
        paid_sesh = None
        free_counter = None
        paid_counter = None

        if ClientSession.query.filter_by(client_id=trans.account_Number, package=PKG_FREE).count() > 0: # check if free session exists 
            free_sesh = ClientSession.query.filter_by(client_id=trans.account_Number, package=PKG_FREE).first() # get free session details
            free_counter = free_sesh.counter
            if free_sesh.limit_type == "mb":
                free_counter = free_sesh.counter / 1000000
            
        if ClientSession.query.filter_by(client_id=trans.account_Number, package=PKG_PAID).count() > 0: # check if paid session exists 
            paid_sesh = ClientSession.query.filter_by(client_id=trans.account_Number, package=PKG_PAID).first() # get paid session details
            paid_counter = paid_sesh.counter
            if paid_sesh.limit_type == "mb":
                paid_counter = paid_sesh.counter / 1000000

        if free_sesh and paid_sesh:
            app.logger.info(f'returned free and paid session details')
            return jsonify({
            free_sesh.package: {
            "counter": free_counter,
            "limit_count": free_sesh.limit_count,
            "limit_type": free_sesh.limit_type,
            },
            paid_sesh.package: {
            "counter": paid_counter,
            "limit_count": paid_sesh.limit_count,
            "limit_type": paid_sesh.limit_type,
            }
        }), 200 # returns session details
        elif free_sesh:
            app.logger.info(f'returned free session details')
            return jsonify({
            free_sesh.package: {
            "counter": free_counter,
            "limit_count": free_sesh.limit_count,
            "limit_type": free_sesh.limit_type,
            }
        }), 200 # returns session details
        elif paid_sesh:
            app.logger.info(f'returned paid session details')
            return jsonify({
            paid_sesh.package: {
            "counter": paid_counter,
            "limit_count": paid_sesh.limit_count,
            "limit_type": paid_sesh.limit_type,
            }
        }), 200 # returns session details
        else:
            app.logger.warning('cannot find sessions associated with the account')
        return "The requested resource could not be found.", 404
    else:
        app.logger.warning('cannot find transaction associated with the given parameter')
        return "The requested resource could not be found.", 404

# <-------------------- DATA ADJUSTMENT ROUTE --------------------->
@app.route('/data-topup', methods=['GET', 'POST'], strict_slashes=False)
def topup(): 
    current_time = datetime.datetime.now(timezone)
    current_date = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
    
    app.logger.info(f'{str(request.remote_addr)} accessed /data with the url: {request.url}')
    account_Number = request.args.get('acc_num', default='', type=str)

    if account_Number == '':
        app.logger.warning('incomplete parameters given')
        return "The request was invalid and cannot be processed.", 400
        
    # For data adjustment on paid packages
    if request.method == 'POST':
        value = request.args.get('value', default=0, type=int)

        if value == '':
            app.logger.warning('no value provided')
            return "The request was invalid and cannot be processed.", 400

        if ClientSession.query.filter_by(account_Number=account_Number, package=PKG_PAID).count() > 0: # check if paid session exists 
            sesh = ClientSession.query.filter_by(account_Number=account_Number, package=PKG_PAID).first() # get details of paid session
            
            sesh.limit_count = int(sesh.limit_count) + value
            sesh.last_modified = current_date
            db.session.commit()

            app.logger.info(f'session limit was successfully updated. new session limit: {sesh.limit_count}')
            return f"{value} {sesh.limit_type} has been added into the session. The session limit is now {sesh.limit_count} {sesh.limit_type}.", 201
        else:
            # if account number exists but paid package is nonexistent, create paid package with given value as limit
            new_session = ClientSession(account_Number=account_Number, package=PKG_PAID, limit_count=value, limit_type=PAID_DATA_TYPE, counter=0, incoming_packets= 0, outgoing_packets=0, created_on=current_time, last_modified=current_date) 
            db.session.add(new_session)
            db.session.commit() 

            return f"{value} {new_session.limit_type} has been added into the session. The session limit is now {new_session.limit_count} {new_session.limit_type}.", 201
            
    else: # FOR GET, return csrf token 
        if Transaction.query.filter_by(account_Number=account_Number).count() > 0: # check if client exists 
            csrf_token = generate_csrf() 
            app.logger.info(f'returned csrf token: {csrf_token}')
            return jsonify({
                "csrf_token": csrf_token
            }), 200 # returns session details
        else:
            app.logger.warning('cannot find paid session associated with the given parameter')
            return "The requested resource could not be found.", 404


# <-------------------- PORTAL (DASHBOARD) ROUTE --------------------->
@app.route('/portal/') 
def portal():
    app.logger.info(f'{str(request.remote_addr)} accessed /ping with the url: {request.url}')

    # Check if the user is connected (has an IP in session)
    if not session.get('ip'):
        return redirect(url_for('logout'))
    
    # Check if the session has a type (e.g., package type) and set it if missing
    if not session.get('type'):
        today = datetime.date.today().strftime('%Y-%m-%d')
        # Simulate a session-based transaction lookup instead of querying the database
        trans = {
            "mac": session.get('mac', '00:00:00:00'),
            "device": session.get('device', 'unknown'),
            "package": "One-Click Login",  # Assuming "One-Click Login" for simplicity
            "last_active": today
        }
        # If we have a valid "transaction" in session, set the package type
        if trans:
            session["type"] = trans['package']
        else:
            return redirect(url_for('logout'))
    
    # Default URL if no redirect link is set
    gw_url = DEFAULT_URL  # Use default as a fallback
    path = gw_url
    
    # Helper function to format data limits
    def format_limit(limit):
        if limit >= 1000000:
            return "{0:.2f} TB".format(limit / 1000000)
        elif limit >= 1000:
            return "{0:.2f} GB".format(limit / 1000)
        else:
            return "{0:.2f} MB".format(limit)

    # Calculate Usage and Limits for Free Access (One-Click Login)
    if session["type"] == "One-Click Login":
        display_type = "Level One"
        daily_limit = FREE_DEFAULT_DATA_LIMIT * 1000000  # daily MB limit
        
        # Simulate device data usage
        device = {
            "mac": session.get("mac", "00:00:00:00"),
            "free_data": session.get("free_data", 10000000),  # Simulate 10 MB used
        }

        # Format the used data and remaining data limits
        daily_used = format_limit(device["free_data"] / 1000000)
        day_rem = daily_limit - device["free_data"] if daily_limit - device["free_data"] >= 0 else 0
        daily_remaining = format_limit(day_rem / 1000000)
    
    # Format limits for display
    ddd_limit = format_limit(daily_limit / 1000000)
    
    # Simulate fetching announcements (could be hardcoded or from another service)
    announcements = ["Welcome to Apollo Wi-Fi!", "Service maintenance on the 15th."]

    # Displays the time elapsed since user login
    # if 'logged_in' in session:
    #     login_time = session['login_time']
    #     logged_in_duration = datetime.datetime.now(timezone) - login_time
    #     time_remaining = datetime.timedelta(minutes=5) - logged_in_duration
    #     if logged_in_duration > datetime.timedelta(minutes=5):
    #         return redirect(url_for('logout'))

    login_history = []
    if session.get('uname'):
        login_history = get_recent_logins(session['uname'])

    return render_template( 
        'portal.html',
        daily_used=daily_used,
        # time_used=logged_in_duration,
        daily_remaining=daily_remaining,
        # time_remaining=time_remaining,
        daily_limit=ddd_limit,
        time_limit=f'N/A',
        announcements=announcements,
        display_type=display_type,
        path=path,
        login_history=login_history
    )

# <-------------------- KEYCLOAK LOGIN ROUTE --------------------->
@app.route('/keycloaksite/')
def keycloaksite(): 
    app.logger.info(f'{str(request.remote_addr)} accessed /ping with the url: {request.url}')
    keycloak_url = "https://wcdssi.apolloglobal.net:8443/auth/realms/workconnect-test/protocol/openid-connect/auth"
    
    # The client details
    client_id = "test-zeep-client"
    redirect_uri = "http://localhost/access" # bug here, localhost cannot be found
    
    # Construct the URL for the Keycloak login page
    auth_url = f"{keycloak_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=openid"
    
    print('redirecting to keycloak login...')
    # Redirect the user to Keycloak's login page
    return redirect(auth_url)

@app.route('/keycloak/', methods=['GET', 'POST'])
def keycloak(): 
    app.logger.info(f'{str(request.remote_addr)} accessed /ping with the url: {request.url}')

    user_agent = parse(session['device'])
    device = f"{user_agent.os.family} / {user_agent.device.family}"
    ip_address=session['ip']

    app.logger.info(f'{device} - {ip_address}')

    current_time = datetime.datetime.now(timezone)
    current_date = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
    
    if request.method == 'POST':
        app.logger.info(f'form submitted')
        # gets parameters from submitted form
        uname = request.form.get('uname', '').strip()
        pword = request.form.get('pword') # encryptPass(request.form.get('pword'))
        otp = request.form.get('otp') 

        payload = {
            'client_id': KEYCLOAK_CLIENT,
            'client_secret': KEYCLOAK_SECRET,
            'username': uname,
            'password': pword,
            'otp': otp,
            'grant_type': 'password',
        }

        try:
            response = requests.post(TOKEN_URL, data=payload)
            token_data = response.json()
            app.logger.info(jsonify({"response body": token_data}))

        except requests.exceptions.RequestException as e: # return an error if the request fails
            app.logger.info(jsonify({"error": "Authentication failed", "details": str(e)}))
            # return render_template('logout.html', message="An error occured while authentication with keycloak.", hideReturnToHome=True)
            return jsonify({"status": "failed", "message": "An error occured while authentication your Keycloak account."})
        
        except Exception as e: # catch any other general exceptions            
            app.logger.error(f"An unexpected error occurred: {str(e)}")
            # return redirect('keycloak.html', message="An unexpected error occurred. Please try again later.", hideReturnToHome=True)
            return jsonify({"status": "failed", "message": "Something went wrong. Please try again later."})
        
        app.logger.info(f'keycloak response code: {response.status_code}')

        if response.status_code == 401:
                app.logger.info("Keycloak authentication failed: Invalid credentials")
                # return render_template('keycloak.html', message="Invalid username or password. Please try again.", hideReturnToHome=True)
                return jsonify({"status": "failed", "message": "Invalid credentials. Please check your username and password and try again."})
        
        if response.status_code == 200: # if response is ok, allow internet access
            package = PKG_UNLI # unlimited for keycloak login
            token = session['token'] 

            trans = Transaction.query.filter_by(token=token).first() # get transaction details via token
            trans.last_active = current_date
            db.session.commit()

            trans.account_Number = uname # update acc_number
            db.session.commit()
            session["uname"] = uname

            # check if client has associated session
            if ClientSession.query.filter_by(account_Number=uname, package=package).count() > 0: # if client has session for unlimited package
                sesh = ClientSession.query.filter_by(account_Number=uname, package=package).first() # get details of session
                
                trans.package = sesh.package
                sesh.last_modified = current_date
                db.session.commit()
                app.logger.info(f'{trans.mac} currently has an active session. proceeding with auth')
                
            # if client does not have session created yet, initialize session
            else:
                app.logger.info(f'client has no session associated with the package. creating session details')
                
                new_session = ClientSession(account_Number=uname, package=package, limit_count=0, limit_type='mb', counter=0, incoming_packets= 0, outgoing_packets=0, created_on=current_time, last_modified=current_date) 
                db.session.add(new_session)
                db.session.commit() 

                trans.package = new_session.package
                db.session.commit() 
            
            # updating transaction details
            trans.stage = "authenticated"
            trans.last_active = current_date

            log = AuthLog(account_Number=uname, mac=trans.mac, gw_id=session['gw_id'], stage="authenticated")
            db.session.add(log)
            db.session.commit()

            session.permanent = True # session persists even after browser closes

            app.logger.info(f'authenticating {trans.mac} with wifidog auth token: http://{trans.gw_address}:{trans.gw_port}/wifidog/auth?token={trans.token}')
            # return redirect(f"http://{trans.gw_address}:{trans.gw_port}/wifidog/auth?token={trans.token}", code=302)
            return jsonify({"status": "redirect", "redirect_url": f"http://{trans.gw_address}:{trans.gw_port}/wifidog/auth?token={trans.token}"})
         # client is given internet access 
        else:
            # return render_template('logout.html', message="Cannot login with keycloak credentials.", hideReturnToHome=True)
            return jsonify({"status": "failed", "message": "Something went wrong. We couldn't log you in with your Keycloak credentials."})
        
    else:
    # Redirect the user to Keycloak's login page
        return render_template('keycloak.html')

# <-------------------- LOGOUT ROUTE --------------------->
@app.route('/logout') 
def logout():
    app.logger.info(f'attempting to log out client... {request.user_agent}')
    if session.get('token'):
        trans = Transaction.query.filter_by(token=session['token']).first()
        if trans:
            trans.stage = "logout"
            trans.date_modified = str(datetime.datetime.now())
            trans.last_active = datetime.datetime.now(timezone).strftime('%Y-%m-%d %H:%M:%S.%f %z')
            db.session.commit()
            app.logger.info(f"successfully logged out client associated with token {session.get('token')}. client will be disconnected within 1 minute")

            app.logger.info('user is being redirected to the logout page...')
            flash("You have been logged out.")
            return render_template('logout.html', message="You have been logged out. Your internet access will automatically be revoked within one (1) minute.")
        else:
            app.logger.warning(f"cannot find client associated with token {session.get('token')}")
            return render_template('logout.html', message="Failed to retrieve client session details. Logout could not be completed.")
            
    else:
        app.logger.warning(f"client's session token not found")
        return render_template('logout.html', message="Client session token not found. Logout failed.")

    # session.clear()

# <-------------------- FUNCTIONS --------------------->
def get_recent_logins(account_number, limit=3):
    """Fetch recent login activity from transactions table"""
    transactions = Transaction.query.filter_by(
        account_Number = account_number
    ).order_by(
        Transaction.last_active.desc()
    ).limit(limit).all()

    login_history = []
    for trans in transactions:
        # Parse the last_active string into a datetime object
        try:
            last_active = datetime.datetime.strptime(
                trans.last_active,
                '%Y-%m-%d %H:%M:%S.%f %z'
            )
        except:
            # Fallback if format doesn't match
            last_active = datetime.datetime.now(timezone)
        
        login_history.append({
            'username': account_number,
            'mac_address': trans.mac,
            'time_ago': pretty_date(last_active)
        })
    return login_history

def pretty_date(time):
    """Convert datetime to human-readable format"""
    now = datetime.datetime.now(timezone)
    diff = now - time

    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "just now"


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)