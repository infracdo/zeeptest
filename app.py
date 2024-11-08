from flask import Flask, request, session, render_template, redirect, flash, url_for, jsonify
from flask_wtf.csrf import CSRFProtect
import os, datetime, hashlib, hmac, threading, time, requests
from sqlalchemy import func 
from models import db, Transaction, AuthLog, Device, ClientSession, Package
from tzlocal import get_localzone
from dateutil import parser
import pytz

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = b'_5#y2L!.4Q8z\n\xec]/'
# Import configurations from .env file
app.config.from_object("config")

timezone = pytz.timezone('Asia/Manila')

clients = {}
_hasRun = False

STATIC_TOKEN = os.environ.get("STATIC_TOKEN")
PACKAGE_TYPE_FREE = os.environ.get("PACKAGE_TYPE_FREE")

POSTGRES = {
    'user': 'wildweasel',
    'pw': 'ap0ll0ap0ll0',
    'db': 'wildweasel',
    'host': 'localhost',
    'port': '5432',
}

portal_url_root = "http://192.168.90.151:8080/"

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# def trackUptime(): # updates timer, last modified, and limit (bool) <------ double check logic
#     app.logger.info(f'current list of clients: {list(clients.keys())}')
#     while True:
#         time.sleep(1)  # Sleep for 1 second
#         current_time = datetime.datetime.now(timezone) # datetime.datetime.now().date() # <------ change to current_date after limit testing
#         if clients: # <------ convert this to database query
#             # [created_on, last_incoming, timer, incoming, outgoing, limit, date_modified]
#             for client in list(clients.keys()): # <----- For tracking client info <------ convert this to database query
#                 previous_incoming = clients[client][1]
#                 timer = clients[client][2]
#                 incoming_packets = clients[client][3]
#                 outgoing_packets = clients[client][4]
#                 date_modified = clients[client][6]

#                 if (previous_incoming is None): # <------ convert this to database query
#                     previous_incoming = 0
#                 else:
#                     previous_incoming = int(previous_incoming)

#                 if (incoming_packets is None and outgoing_packets is None): # <------ convert this to database query
#                     incoming_packets = 1
#                     outgoing_packets = 1
#                 else:
#                     incoming_packets = int(incoming_packets)
#                     outgoing_packets = int(outgoing_packets)

#                 if (previous_incoming != incoming_packets): # if there is a difference then client is active <------ convert this to database query
#                     if (datetime.timedelta(seconds=int(timer)) > datetime.timedelta(seconds=0)): # if timer > 0 decrease timer <------ convert this to database query
#                     # if (datetime.timedelta(seconds=timer) < datetime.timedelta(minutes=TIME_LIMIT)): # if timer < time limit increase timer
#                         if(incoming_packets + outgoing_packets > 1.0):
#                             clients[client][2] = int(clients[client][2]) - 1
#                             clients[client][6] = current_time # updates last modified date

#                         app.logger.info(f'current timer for {client}: {clients[client][2]} seconds previous incoming: {clients[client][1]} incoming: {clients[client][3]} outgoing: {clients[client][4]} last modified: {clients[client][6]}')
#                     else: # update client's limit status
#                         clients[client][5] = True
#                         clients[client][6] = current_time # updates last modified date

# Generates new token based on secret key and mac address 
def genToken(mac): # generates 1 unique token per mac address
    secret_key = b'apollo' # <---- What if secret_key is transaction.created_on or transaction.id 
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

# @app.before_request
# def firstRun():
#     global _hasRun
    # if not _hasRun: # allow thread to run once
    #     _hasRun = True
    #     thread = threading.Thread(target=trackUptime, args=())
    #     thread.daemon = True  # Allow thread to exit when main program does
    #     thread.start()

# <-------------------- ROUTES --------------------->
@app.route('/wifidog/ping', strict_slashes=False)
@app.route('/ping', strict_slashes=False)
def ping():
    app.logger.info(f'{str(request.remote_addr)} accessed /ping with the url: {request.url}')
    return "Pong"

# <-------------------- LOGIN ROUTE --------------------->
@app.route('/wifidog/login/', methods=['GET', 'POST'], strict_slashes=False)
@app.route('/login/', methods=['GET', 'POST'], strict_slashes=False)
def login(): 
    current_time = datetime.datetime.now(timezone)
    current_date = current_time.strftime("%Y-%m-%d") # datetime.datetime.now().date() # <------ change to current_date after limit testing

    # For form submission
    if request.method == 'POST':
        # gets parameters from submitted form
        uname = request.form.get('uname')
        pword = encryptPass(request.form.get('pword'))
        package = request.form.get('package')
        token = session['token'] # STATIC_TOKEN

        # if not session.get('gw_address') or not session.get('gw_port'):
        #     flash("Gateway information is missing")
        #     return redirect(url_for('login'))

        # initialize limit for session_tracker here
        if package == "Free": 
            # check if trans should be created
            trans = Transaction.query.filter_by(token=token).order_by(Transaction.created_on.desc()).first() # get details of client's latest transaction  
            device = Device.query.filter_by(id=trans.device_id).first() # get device details
            package = Package.query.filter_by(package_type=PACKAGE_TYPE_FREE).first() # get details of free package

            if ClientSession.query.filter_by(cluster_id=trans.cluster_id, package_id=package.id).count() > 0: # if transaction has free package session
                sesh = ClientSession.query.filter_by(cluster_id=trans.cluster_id, package_id=package.id).first() # get details of latest associated session

                if sesh.limit_reached: # if the free package session has reached its limit
                    if current_time - datetime.datetime.strptime(sesh.date_modified, "%Y-%m-%d %H:%M:%S.%f %z") < datetime.timedelta(minutes=10): # check if session.date_modified is less than 10 minutes of current_time then deny auth (FOR TESTING PURPOSES, please change to date)
                        msg = "You have used up your free daily package for today."
                        if package.limit_type == "mb":
                            msg = "You have exceeded your free data usage limit for today."
                        elif package.limit_type == "min":
                            msg = "You have exceeded your free time limit for today."
                        app.logger.info(f"{device.mac} has reached the limit for today. denying auth")
                        return render_template('logout.html', message=msg, returnLink=url_for('access'), return_text="Back")
                    else:
                        app.logger.info(f"{device.mac}'s limit has been reset. authenticating client")
                    
                else: # client has session for free package but it is still not expired: allow auth and update session.incoming_packets, session.outgoing_packets, device.last_active
                    app.logger.info(f"{device.mac} has not reached today's limit. authenticating client")

            # if client does not have free session created today, create session and status
            else: # client has no active session today: allow auth, create session and session_status for free package, and update device.last_active
                app.logger.info(f'device has no free package session. creating session and status entry')
                new_session = ClientSession(device_id=device.id, package_id=package.id, cluster_id=trans.cluster_id, counter=0, incoming_packets= 0, outgoing_packets=0, limit_reached=False, created_on=current_time, date_modified=current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z'))
                db.session.add(new_session)
                db.session.commit()
            
            new_trans = trans
            new_trans.stage = "authenticated"
            new_trans.package_id = package.id
            new_trans.cluster_id = trans.cluster_id
            new_trans.uname = device.mac
            session["uname"] = trans.uname
            new_trans.date_modified = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
            new_trans.created_on = current_time
            db.session.add(new_trans)
            db.session.commit()

            log = AuthLog(gw_id=session['gw_id'], stage="authenticated", mac=device.mac, uname=new_trans.uname)
            db.session.add(log)
            device.last_active = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
            db.session.commit()

            session.permanent = True # session is set to permanent, clear the session based on a specific requirement

            # Redirect to the access point with token (Gateway Address: 1.2.3.4, Port: 2060)
            app.logger.info(f'authenticating {device.mac} with wifidog auth token..')
            return redirect(f"http://{trans.gw_address}:{trans.gw_port}/wifidog/auth?token={trans.token}", code=302)
        
    else: # For GET request, on first connection, captive portal redirects here

        if request.headers.get('isHTTPS') == "no": # if request url is http then redirect to portal
            path = str(request.url).replace(str(request.url_root),portal_url_root,1)
            print(path)
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
        session['token'] = request.cookies.get('token') # STATIC_TOKEN
        session['device'] = request.headers.get('User-Agent')
        session['logged_in'] = True
        session.modified = True
        
        # catch errors: if no IP, if not accessed through wifi, redirect
        if session['ip'] == '' or session['ip'] == None:
            return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
        
        # if device exists in database, update last active
        if Device.query.filter_by(mac=session['mac']).count() > 0:
            device = Device.query.filter_by(mac=session['mac']).first()
            device.last_active = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
        else: # add to database if new device
            new_device = Device(mac=session['mac'], total_incoming_packets=0, total_outgoing_packets=0, last_active=current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z'))
            db.session.add(new_device)
        db.session.commit()

        device = Device.query.filter_by(mac=session['mac']).first() # retrieve device details via mac

        #### FIX LOGIN LOGIC FOR GET 
        if Transaction.query.filter_by(device_id=device.id, device=session['device']).count() > 0: # check if device has a capture/authenticated transaction 
            trans = Transaction.query.filter_by(device_id=device.id, device=session['device']).order_by(Transaction.created_on.desc()).first() # retrieves details of client's latest capture/authenticaated transaction
            app.logger.info(f'found recent transaction for {device.mac} with id: {trans.id}, stage:{trans.stage}, and token {trans.token} ')

            session['token'] = trans.token

            ## check if transaction has session via cluster_id
            if ClientSession.query.filter_by(cluster_id=trans.cluster_id).count() > 0:
                sesh = ClientSession.query.filter_by(cluster_id=trans.cluster_id).first() # gets session details associated with transaction
                if sesh.limit_reached: # if session has reached limit
                    if current_time - datetime.datetime.strptime(sesh.date_modified, "%Y-%m-%d %H:%M:%S.%f %z") > datetime.timedelta(minutes=10): # if it has been more than 10 minutes after last modified then reset token
                        session['token'] = None # reset session token to force create new transaction
                        app.logger.info(f'limit for {device.mac} has been reset')
                else: # if session has not hit limit then use current token
                    app.logger.info(f'{device.mac} currently has an active session. using transaction token')
            else: # for stage=capture transactions
                app.logger.info(f"{device.mac}'s current transaction is not associated with an active session")

        # if token is null, generate token for client
        if session['token'] == None:
            app.logger.info(f'cannot find token for session. creating new transaction')
            genToken(session['mac']) # generate token based on client mac            
            # create new client transaction
            trans = Transaction(gw_sn=session['gw_sn'], gw_id=session['gw_id'], ip=session['ip'], gw_address=session['gw_address'], gw_port=session['gw_port'], device_id=device.id, apmac=session['apmac'], ssid=session['ssid'], vlanid=session['vlanid'], token=session['token'], stage="capture", device=session['device'], date_modified=current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z'), created_on=current_time)
            db.session.add(trans)
            db.session.commit()

            trans.cluster_id = trans.id
            db.session.commit()
            
            log = AuthLog(stage="capture", gw_id=session['gw_id'], mac=session['mac'])
            db.session.add(log)
            # create new log.
            db.session.commit()
        else:
            app.logger.info(f"found token for {device.mac}'s current transaction. updating transaction")
            # if client already has token, get details of capture/authenticated transaction and update details
            trans = Transaction.query.filter_by(token=session['token']).order_by(Transaction.created_on.desc()).first()
            trans.date_modified = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
            log = AuthLog(stage=trans.stage, gw_id=session['gw_id'], mac=session['mac'])
            db.session.add(log)
            db.session.commit()

        return render_template('index.html')
        

# <-------------------- INSTANT ACCESS ROUTE --------------------->
@app.route('/access/')
def access():

    # Check if there is a gateway ID stored in session
    if not session.get('gw_id'):
        flash("Gateway ID is missing in session.")
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
    current_date = current_time.strftime("%Y-%m-%d")

    # retrieve parameters from request url
    mac_n = request.args.get('mac', default='', type=str)
    token_n = request.args.get('token', default='', type=str)
    stage_n = request.args.get('stage', default='', type=str)
    incoming_n = request.args.get('incoming')
    outgoing_n = request.args.get('outgoing')
    trans = Transaction.query.filter_by(token=token_n).order_by(Transaction.created_on.desc()).first() # get transaction details from token

    app.logger.info(f'client mac: {mac_n} token_n: {token_n} stage_n: {stage_n} incoming: {incoming_n} outgoing: {outgoing_n}')

    # Check if there is a token
    if not token_n:
        app.logger.warning('no token provided')
        return "No authentication token provided.", 403

    app.logger.info('session transaction: ' + str(dict(session)))

    if not trans.created_on:
        trans.created_on = current_time
        db.session.commit()
    
     # <------ Logouts client ------>
    app.logger.info(f'reached auth stage=logout checker')
    if stage_n == "logout": # cuts connection during logout stage and updates database
        new_trans = trans
        new_trans.stage = "logout"
        new_trans.date_modified = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
        db.session.add(new_trans)
        db.session.commit()
        
        device = Device.query.filter_by(id=trans.device_id).first()
        device.last_active = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
        db.session.commit()

        log = AuthLog(gw_id=trans.gw_id, stage="logout", mac=device.mac, uname=trans.uname)
        db.session.add(log)
        db.session.commit()
        app.logger.warning(f'{device.mac} is being logged out')
        return "Auth: 0"

    if trans.stage == "logout":
        app.logger.warning(f'{device.mac} has been logged out')
        return "Auth: 0"
    
    app.logger.info(f'reached auth stage=counter checker')
    # <------ Updates counter ------>
    if 'counter' in stage_n.lower() and not (trans.created_on == None or trans.created_on == ''): 
        # check if package type is mb or min
        if Package.query.filter_by(id=trans.package_id).count() > 0:
            package = Package.query.filter_by(id=trans.package_id).first() # gets package info from device id
            sesh = ClientSession.query.filter_by(cluster_id=trans.cluster_id).first() # gets session info from device id
            device = Device.query.filter_by(id=trans.device_id).first()

            last_incoming_packets = int(sesh.incoming_packets) # store previous incoming packets for comparison
            
            # evaluates packets from auth
            if int(incoming_n) != 0 and int(outgoing_n) != 0: # if neither values are 0, data is being exchanged
 
                sesh.incoming_packets = int(sesh.incoming_packets) + int(incoming_n) # update new incoming packet
                sesh.outgoing_packets = int(sesh.incoming_packets) + int(outgoing_n) # update new outgoing packet
                sesh.date_modified = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
                db.session.commit()

                if int(incoming_n) != last_incoming_packets: # if new and old incoming packets are different, there is new activity
                    
                    if package.limit_type == "mb":
                        sesh.counter = int(incoming_n) + int(outgoing_n)
                    elif package.limit_type == "min":
                        sesh.counter = int(sesh.counter) + 1
                    sesh.date_modified = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
                    device.last_active = current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
                    db.session.commit()

                    app.logger.info(f'current {device.mac} session counter is {sesh.counter / 1000000} mb')
                    app.logger.info(f'{device.mac} is using their data')

                else: # if new incoming and old incoming packets are the same then there is no new activity from client 
                    app.logger.info(f'{device.mac} is idle')
                    return "Auth: 0" # disconnect client if idle

            else: # if incoming and outgoing packets are 0 then client has no internet activity
                app.logger.info(f'{device.mac} has yet to send/receive data')

            # Update session info if successful authentication
            session['stage'] = stage_n

            # evaluates if client should still be connected
            package_limit = package.limit
            if package.limit_type == "mb":
                package_limit = package.limit * 1000000
            if (sesh.counter >= package_limit): #if client hits limit then update status limit and disconnect
                sesh.limit_reached=True 
                sesh.date_modified=current_time.strftime('%Y-%m-%d %H:%M:%S.%f %z')
                db.session.commit()
                app.logger.info(f'informed {str(request.remote_addr)} to disconnect {mac_n}')
                return "Auth: 0"
            else:
                app.logger.info(f'informed {str(request.remote_addr)} to keep {mac_n} connected')
                return "Auth: 1"
        
        app.logger.warning(f'package not found')
    
    ## RECHECK LOGIC 
    app.logger.info(f'reached auth one-click login checker')
    # <------ Authenticates client after one-click login ------>
    package_id = Package.query.filter_by(package_type=PACKAGE_TYPE_FREE).first().id # get package id of free package
    if int(trans.package_id) == int(package_id): # if transaction package is one-click login, check if sesh hit limit
        sesh = ClientSession.query.filter_by(cluster_id=trans.cluster_id).first() # get details of session associated with transaction 
        if sesh.limit_reached:
            app.logger.warning(f'{mac_n} has reached limit. logging out client')
            return "Auth: 0"
        else:
            app.logger.info(f'{mac_n} has not reached limit. client is authenticated')
            return "Auth: 1"

    app.logger.warning('reached the end of /auth')
    return "Auth: 0"


# <-------------------- PORTAL (DASHBOARD) ROUTE --------------------->
@app.route('/portal/') 
def portal():
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
            "date_modified": today
        }
        # If we have a valid "transaction" in session, set the package type
        if trans:
            session["type"] = trans['package']
        else:
            return redirect(url_for('logout'))
    
    # Default URL if no redirect link is set
    #default_url = 'http://speedtest.apollo.com.ph/'
    default_url = 'https://fast.com/'
    # Hardcode a portal redirect URL for the session's gateway, if applicable
    gw_url = default_url  # Use default as a fallback
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
        daily_limit = 50000000  # 50 MB daily limit
        
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

    return render_template( 
        'portal.html',
        daily_used=daily_used,
        # time_used=logged_in_duration,
        daily_remaining=daily_remaining,
        # time_remaining=time_remaining,
        daily_limit=ddd_limit,
        time_limit='5 minutes',
        announcements=announcements,
        display_type=display_type,
        path=path
    )

@app.route('/logout')
def logout():
    app.logger.info('attempting to log out user...')
    print('session before clear: ' + str(dict(session)))
    gw_address= session.get('gw_address', '1.2.3.4')
    gw_port= session.get('gw_port', '2060')
    token= session.get('token', STATIC_TOKEN)

    app.logger.info('session gw_address: ' + str(gw_address) + ' gw_port: ' + str(gw_port) + ' token: ' + str(token))

    session.clear()
    print('session after clear: ' + str(dict(session)))

    app.logger.info('user has been redirected to log out page...')
    flash("You have been logged out.")
    return render_template('logout.html', message="You have been logged out.")

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)