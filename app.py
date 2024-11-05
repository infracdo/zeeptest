from flask import Flask, request, session, render_template, redirect, flash, url_for, jsonify
from flask_wtf.csrf import CSRFProtect
import datetime, hashlib, hmac, threading, time, requests
from sqlalchemy import text 
from sqlalchemy.orm import joinedload
from models import db, Transaction, AuthLog, Device, ClientSession, SessionStatus, Package
from tzlocal import get_localzone
import pytz

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = b'_5#y2L!.4Q8z\n\xec]/'
# Import configurations from .env file
app.config.from_object("config")

timezone = pytz.timezone('UTC')

clients = {}
_hasRun = False

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

# Temporary CSRF token for authentication
STATIC_TOKEN = "3b1f1e2f55c34c5b9f8c4e1a7b83e4d0"
# TIME_LIMIT = 5

def trackUptime(): # updates timer, last modified, and limit (bool) <------ double check logic
    app.logger.info(f'current list of clients: {list(clients.keys())}')
    while True:
        time.sleep(1)  # Sleep for 1 second
        current_time = datetime.datetime.now(timezone) # datetime.datetime.now().date() # <------ change to current_date after limit testing
        if clients: # <------ convert this to database query
            # [created_on, last_incoming, timer, incoming, outgoing, limit, date_modified]
            for client in list(clients.keys()): # <----- For tracking client info <------ convert this to database query
                previous_incoming = clients[client][1]
                timer = clients[client][2]
                incoming_packets = clients[client][3]
                outgoing_packets = clients[client][4]
                date_modified = clients[client][6]

                if (previous_incoming is None): # <------ convert this to database query
                    previous_incoming = 0
                else:
                    previous_incoming = int(previous_incoming)

                if (incoming_packets is None and outgoing_packets is None): # <------ convert this to database query
                    incoming_packets = 1
                    outgoing_packets = 1
                else:
                    incoming_packets = int(incoming_packets)
                    outgoing_packets = int(outgoing_packets)

                if (previous_incoming != incoming_packets): # if there is a difference then client is active <------ convert this to database query
                    if (datetime.timedelta(seconds=int(timer)) > datetime.timedelta(seconds=0)): # if timer > 0 decrease timer <------ convert this to database query
                    # if (datetime.timedelta(seconds=timer) < datetime.timedelta(minutes=TIME_LIMIT)): # if timer < time limit increase timer
                        if(incoming_packets + outgoing_packets > 1.0):
                            clients[client][2] = int(clients[client][2]) - 1
                            clients[client][6] = current_time # updates last modified date

                        app.logger.info(f'current timer for {client}: {clients[client][2]} seconds previous incoming: {clients[client][1]} incoming: {clients[client][3]} outgoing: {clients[client][4]} last modified: {clients[client][6]}')
                    else: # update client's limit status
                        clients[client][5] = True
                        clients[client][6] = current_time # updates last modified date

# Generates new token based on secret key and mac address
def genToken(mac):
    secret_key = b'apollo' 
    hashed_mac = mac.encode('utf-8')
    hmac_object = hmac.new(secret_key, hashed_mac, hashlib.sha256)
    hmac_hex = hmac_object.hexdigest()[:32]

    app.logger.info('token generated: '+ hmac_hex + ' from mac: '+ mac)

    session['token'] = hmac_hex # uuid.uuid4().hex
    session.modified = True

# Encrypt the password submitted from form
def encryptPass(password):
    return password[::-1]

# # For future purposes in setting limitations
# def getLimit(gw_id, user_id, type_, default_limit):
#     return default_limit

# def getFreePackage(device): 
#     # check if device has active sessions
#     if ClientSession.query.filter_by(device_id=device.device_id).count() > 0:
#         device_sessions = ClientSession.query.filter( # gets all session associated with device id
#             ClientSession.device_id == device.device_id
#         ).all()

#         if device_sessions: # CHECK CODE LOGIC 
#             for session in device_sessions: # for each session associated with the device, check if their status is active
#                 if SessionStatus.query.filter_by(session_id=session.id, limit_reached=False).count() > 0: # if session limit is not reached, check package type
#                     if Package.query.filter_by(id=session.package_id, package_type="One-Click Login").count() > 0: # if 
#                         return session.id
#     return None

@app.before_request
def firstRun():
    global _hasRun
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
    global session
    current_time = datetime.datetime.now(timezone)
    current_date = str(datetime.datetime.now(timezone)) # datetime.datetime.now().date() # <------ change to current_date after limit testing
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

        ### DOUBLE CHECK LOGIC
        # initialize limit for session_tracker here
        if package == "Free":
            trans = Transaction.query.filter_by(token=token).first() # get transaction details via token
            # check if device has active sessions
            if ClientSession.query.filter_by(device_id=trans.device_id).count() > 0: ## Code can be simplified if we assume there is only 1 active session per client
                device_sessions = ClientSession.query.filter(ClientSession.device_id == trans.device_id).all() # gets all of client's sessions

                if device_sessions: # CHECK CODE LOGIC 
                    for session in device_sessions: # for each session associated with the device, check if their status is complete
                        if datetime.strptime(session.created_on, "%Y-%m-%d %z").date() == current_date and Package.query.filter_by(id=session.package_id, package_type="One-Click Login").count() > 0: # if session is created today and package type is free
                            if SessionStatus.query.filter_by(session_id=session.id, limit_reached=True).count() > 0: # check if the free session that was created today has reached its limit
                                package = Package.query.filter_by(id=session.package_id, package_type="One-Click Login").first()
                                msg = "You have used up your free package for today."
                                if package.counter_type == "mb":
                                    msg = "You have exceeded your data usage limit for today."
                                elif package.counter_type == "min":
                                    msg = "You have exceeded your time limit for today."
                                return render_template('logout.html', message=msg, returnLink=url_for('access'), return_text="Back")
                            else:
                                app.logger.info("client has not reached today's limit")
                        else: # generate session entry if client hasnt availed a free package today
                            app.logger.info('client hasnt availed free package today')
                            sesh = ClientSession(mac=session['mac'], last_in_packets=None, counter=5, in_packets=None, out_packets=None, expired=False, package='Free', counter_type='min', date_modified=current_date, created_on=current_time)
                            db.session.add(sesh)
                            db.session.commit()

            # get package_id and 
            trans.stage = "authenticated"
            trans.package_id = "One-Click Login"
            trans.uname = device.mac
            session["uname"] = trans.uname
            trans.date_modified = current_time
            trans.created_on = current_time
            log = AuthLog(gw_id=session['gw_id'], stage="authenticated", mac=trans.mac, username=trans.uname)
            db.session.add(log)
            db.session.commit()

            session.permanent = True # session is set to permanent, clear the session based on a specific requirement

            # Redirect to the access point with token (Gateway Address: 1.2.3.4, Port: 2060)
            return redirect(f"http://{trans.gw_address}:{trans.gw_port}/wifidog/auth?token={trans.token}", code=302)
        
    else: # For GET request, on first connection, captive portal redirects here

        if request.headers.get('isHTTPS') == "no":
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
            device.last_active = current_time
            db.session.commit()
        else: # add to database if new device
            new_device = Device(mac=session['mac'], last_incoming_packets=None, incoming_packets=None, outgoing_packets=None, last_active=current_time)
            db.session.add(new_device)
            db.session.commit()

        device_id = Device.query.filter_by(mac=session['mac']).first().id # retrieve device details via mac

        # if client has previous transactions, get token 
        if Transaction.query.filter_by(device_id=device_id, device=session['device']).count() > 0:
            session['token'] = Transaction.query.filter_by(device_id=device_id, device=session['device']).first().token

        # if token is null, generate token for client
        if session['token'] == None:
            genToken(session['mac']) # generate token based on client mac            
            # create new client transaction
            trans = Transaction(gw_sn=session['gw_sn'], gw_id=session['gw_id'], ip=session['ip'], gw_address=session['gw_address'], gw_port=session['gw_port'], device_id=device_id, apmac=session['apmac'], ssid=session['ssid'], vlanid=session['vlanid'], token=session['token'], stage="capture", device=session['device'], date_modified=current_date, created_on=current_time)
            db.session.add(trans)
            log = AuthLog(stage="capture", gw_id=session['gw_id'], mac=session['mac'])
            db.session.add(log)
            # create new log.
            db.session.commit()
        else:
            # if client already has token, update the database entry
            trans = Transaction.query.filter_by(token=session['token']).first()
            trans.gw_sn = session['gw_sn']
            trans.gw_id = session['gw_id']
            trans.ip = session['ip']
            trans.gw_address = session['gw_address']
            trans.gw_port = session['gw_port']
            trans.device_id = device_id
            trans.apmac = session['apmac']
            trans.ssid = session['ssid']
            trans.vlanid = session['vlanid']
            trans.stage = "capture"
            trans.device = session['device']
            trans.date_modified = current_date
            log = AuthLog(stage="capture", gw_id=session['gw_id'], mac=session['mac'])
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
    current_date = str(datetime.datetime.now(timezone))

    # retrieve parameters from request url
    mac_n = request.args.get('mac', default='', type=str)
    token_n = request.args.get('token', default='', type=str)
    stage_n = request.args.get('stage', default='', type=str)
    incoming_n = request.args.get('incoming')
    outgoing_n = request.args.get('outgoing')
    trans = Transaction.query.filter_by(token=token_n).first() # gets transaction details from token

    app.logger.info(f'client mac: {mac_n} token_n: {token_n} stage_n: {stage_n} incoming: {incoming_n} outgoing: {outgoing_n}')

    # Check if there is a token
    if not token_n:
        return "No authentication token provided.", 403

    app.logger.info('session transaction: ' + str(dict(session)))

    if not trans.created_on:
        trans.created_on = current_time
        db.session.commit()


    # <------ Logouts client ------>
    if stage_n == "logout": # stops connection during logout stage and updates database
        trans.stage = "logout"
        trans.date_modified = current_date
        db.session.commit()

        device = Device.query.filter_by(id=trans.device_id).first()
        device.last_active = current_date
        db.session.commit()

        trans.stage = "logout"
        trans.date_modified = current_date
        db.session.commit()
        return "Auth: 0"

    if trans.stage == "logout":
        return "Auth: 0"

    # <------ Update counter ------>
    if stage_n == "counters" and not (trans.created_on == None or trans.created_on == ''):
        # check if package type is mb or min
        if Package.query.filter_by(id=trans.package_id).count() > 0:
            package = Package.query.filter_by(id=trans.package_id).first() # gets package info from device id
            session = ClientSession.query.filter_by(device_id=trans.device_id).first() # gets session info from device id
            device = Device.query.filter_by(id=trans.device_id).first()

            # evaluates packets from auth
            if incoming_n != 0 and outgoing_n != 0: # if neither new values are 0, data is being exchanged
                if incoming_n != device.incoming_packets: # if new and stored incoming arent same, there is new activity
                    # device.last_incoming_packets = device.incoming_packets # store old packet
                    device.incoming_packets = incoming_n # update new incoming packet
                    device.outgoing_packets = outgoing_n # update new outgoing packet
                    device.last_active = current_date

                    if package.limit_type == "mb":
                        session.counter = int(device.incoming_packets) + int(device.outgoing_packets)
                    elif package.limit_type == "min":
                        session.counter = int(session.counter) + 1
                        session.date_modified = current_date
                    db.session.commit()
                    app.logger.info(f'{device.mac} is using their data')
                else: # if there is no new activity from client
                    app.logger.info(f'{device.mac} is idle')
            else: # if client has no internet activity
                app.logger.info(f'{device.mac} has yet to send/receive data')
            
            app.logger.info(f'{device.mac} last in: {device.last_incoming_packets}, stored in: {device.incoming_packets}, new in: {incoming_n}, stored out: {device.outgoing_packets}, new out: {outgoing_n}')

            # Update session info if successful authentication
            session['stage'] = stage_n

            # evaluates if client should still be connected
            if (session.counter >= package.limit): #if client hits counter limit, return true
                app.logger.info(f'informed {str(request.remote_addr)} to disconnect {mac_n}')
                ### update database to reflect change
                return "Auth: 0"
            else:
                app.logger.info(f'informed {str(request.remote_addr)} to keep {mac_n} connected')

                return "Auth: 1"
        
        app.logger.warning(f'package not found')
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
    app.run(debug=True, host="0.0.0.0", port=80)