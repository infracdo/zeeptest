from flask import Flask, request, session, render_template, redirect, flash, url_for, jsonify
from flask_wtf.csrf import CSRFProtect
import datetime, hashlib, hmac, threading, time, requests

from tzlocal import get_localzone
import pytz

app = Flask(__name__)
# Import configurations from .env file
app.config.from_object("config")

csrf = CSRFProtect(app)

timezone = pytz.timezone('UTC')

clients = {}
counter = 0
trackUser = False 
_hasRun = False

# Temporary CSRF token for authentication
STATIC_TOKEN = "3b1f1e2f55c34c5b9f8c4e1a7b83e4d0"
TIME_LIMIT = 5

def trackUptime(): # updates counter, last modified, and limit (bool) <------ double check logic
    while True:
        time.sleep(1)  # Sleep for 1 second
        if clients:
            # [created_at, data_used, counter_in_seconds, incoming, outgoing, limit, last_incoming, last_modified_date]
            for client in list(clients.keys()): # <----- For tracking client info
                if (last_modified_date is not datetime.datetime.now().date()): # reset counter if last modified date is not today
                    clients[client][2] = 0 # resets counter
                    clients[client][3] = 0 # resets incoming
                    clients[client][4] = 0 # resets outgoing
                    clients[client][5] = False # resets limit
                    clients[client][6] = 0 # resets last_incoming
                    clients[client][7] = datetime.datetime.now().date() # updates last modified date
                    app.logger.info(f"client {client}'s limit has been reset")

                counter_in_seconds = clients[client][2]
                incoming_packets = clients[client][3]
                outgoing_packets = clients[client][4]
                previous_incoming = clients[client][6]
                last_modified_date = clients[client][7]

                if (incoming_packets is None and outgoing_packets is None):
                    incoming_packets = 1
                    outgoing_packets = 1
                else:
                    incoming_packets = int(incoming_packets)
                    outgoing_packets = int(outgoing_packets)

                if (previous_incoming is not incoming_packets): # if there is a difference then client is active
                    if (datetime.timedelta(seconds=counter_in_seconds) < datetime.timedelta(minutes=TIME_LIMIT)): # if counter < time limit increase counter
                        if(incoming_packets + outgoing_packets > 1.0):
                            clients[client][2] += 1
                            clients[client][7] = datetime.datetime.now().date() # updates last modified date

                        app.logger.info(f'current counter for {client}: {clients[client][2]} seconds previous incoming: {clients[client][6]} incoming: {clients[client][3]} outgoing: {clients[client][4]} last modified: {clients[client][7]}')
                    else: # update client's limit status
                        clients[client][5] = True
                        clients[client][7] = datetime.datetime.now().date() # updates last modified date

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

# For future purposes in setting limitations
def getLimit(gw_id, user_id, type_, default_limit):
    return default_limit

@app.before_request
def firstRun():
    global _hasRun
    if not _hasRun: # allow thread to run once
        _hasRun = True
        thread = threading.Thread(target=trackUptime, args=())
        thread.daemon = True  # Allow thread to exit when main program does
        thread.start()

# <-------------------- ROUTES --------------------->
@app.route('/wifidog/ping', strict_slashes=False)
@app.route('/ping', strict_slashes=False)
def ping():
    return "Pong"

# <-------------------- LOGIN ROUTE --------------------->
@app.route('/wifidog/login/', methods=['GET', 'POST'], strict_slashes=False)
@app.route('/login/', methods=['GET', 'POST'], strict_slashes=False)
def login():
    global trackUser
    # For form submission
    if request.method == 'POST':
        uname = request.form.get('uname')
        pword = encryptPass(request.form.get('pword'))
        package = request.form.get('package')
        if session['token'] == None:
            genToken(session['mac'])
        token = session['token'] # STATIC_TOKEN
        session['login_time'] = datetime.datetime.now(timezone)
        app.logger.info('login time is: ' + str(session['login_time']))

        if not session.get('gw_address') or not session.get('gw_port'):
            flash("Gateway information is missing")
            return redirect(url_for('login'))

        # Free 
        if package == "Free":
            daily_limit = getLimit(session['gw_id'], 1, 'dd', 50000000)
            month_limit = getLimit(session['gw_id'], 1, 'mm', 1000000000)
            session['type'] = 'One-Click Login'

            # Mock data to simulate user session and transaction
            session["uname"] = session['mac']
            trans = {
                "stage": "authenticated",
                "package": "One-Click Login",
                "uname": session['mac'],
                "mac": session['mac'],
                "ip": session['ip'],
                "gw_address": session['gw_address'],
                "gw_port": session['gw_port'],
                "token": token,
                "device": session['device']
            }
            trackUser = True
            session.permanent = True # session is set to permanent, clear the session based on a specific requirement
            # app.permanent_session_lifetime = datetime.timedelta(minutes=1)
            session.modified = True

            # <------ Initializes client info ------>
            created_at = datetime.datetime.now()
            last_modified_date = datetime.datetime.now().date()

            clients[session['mac']] = [created_at, 0, 0, None, None, False, 0, last_modified_date] # <----- Stores client info in a dict
            app.logger.info(f"client info: {clients.get(session['mac'])}")

            # Check if redirected to access point
            app.logger.info(f"Redirecting to: http://{trans['gw_address']}:{trans['gw_port']}/wifidog/auth?token={trans['token']}")

            # Redirect to the access point with token (Gateway Address: 1.2.3.4, Port: 2060)
            return redirect(f"http://{trans['gw_address']}:{trans['gw_port']}/wifidog/auth?token={trans['token']}", code=302)
        
    else: # For GET request
        # Retrieving parameters and storing in session
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

        app.logger.info('session transaction: ' + str(dict(session)))
        session.modified = True
        
        app.logger.info('user mac address: ' + str(session['mac']) + 'with token: ' + str(session['token']))

        # catch errors: if no IP, if not accessed through wifi, redirect
        if session['ip'] == '' or session['ip'] == None:
            return render_template('logout.html', message="Please connect to the portal using your WiFi settings.", hideReturnToHome=True)
        
        # check if client mac already exists, if exists then redirect to logout, if doesnt exist then proceed to access
        if (session['mac'] in clients and clients[session['mac']][5]): # if client is already existing and already hit limit, return to logout
            return render_template('logout.html', message="You have already reached the limit for today. Please try again tomorrow.", hideReturnToHome=True)
        else:
            # Display the main page (index.html) when user is redirected to the captive portal
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
    app.logger.info('someone is accessing /auth with ip:' + str(request.remote_addr))
    # return "Auth: 0" # emergency logout button (uncomment and wait for AP to request to server)

    mac_n = request.args.get('mac', default='', type=str)
    token_n = request.args.get('token', default='', type=str)
    stage_n = request.args.get('stage', default='', type=str)
    incoming_n = request.args.get('incoming')
    outgoing_n = request.args.get('outgoing')
    previous_incoming = clients[mac_n][6]
    clients[mac_n][3] = incoming_n
    clients[mac_n][4] = outgoing_n

    app.logger.info(f'client mac: {mac_n} token_n: {token_n} stage_n: {stage_n} previous incoming: {previous_incoming} current incoming: {incoming_n} current outgoing: {outgoing_n}')

    # Check if there is a token
    if not token_n:
        return "No authentication token provided.", 403

    # Simulate a session-based transaction
    trans = {
        "token": session.get("token"),
        "uname": session.get("uname", "guest"),
        "mac": session.get("mac", "00:00:00:00"),
        "gw_id": session.get("gw_id", "gateway"),
        "ip": session.get("ip", "0.0.0.0"),
        "package": session.get("package", "One-Click Login"),
        "device": session.get("device", "unknown"),
        "octets": session.get("octets", 0)
    }

    app.logger.info('session transaction: ' + str(dict(session)))

    # Simulate limit retrievals
    daily_limit = 50000000  # 50 MB
    month_limit = 1000000000  # 1 GB
    octets = trans['octets']

    # Free Access Authentication
    if trans['package'] == "One-Click Login":
        # Simulate tracking usage
        new_record = int(incoming_n) + int(outgoing_n)
        session['last_record'] = new_record
        consumed_day = new_record  # Dummy tracking daily usage
        consumed_month = new_record  # Dummy tracking monthly usage

        # Check if limits exceeded (dummy)
        if consumed_day >= daily_limit or consumed_month >= month_limit:
            # Simulate stopping the connection (dummy)
            return redirect(url_for('logout'))
        else:
            # Simulate updating interim session usage (dummy)
            session['octets'] = incoming_n + outgoing_n

    # Update session info if successful authentication
    session['stage'] = stage_n
    session['octets'] = incoming_n + outgoing_n
    session['last_active'] = str(datetime.datetime.now())

    if (clients[mac_n][5]): #if client hits limit, return true
        app.logger.info(f'client {mac_n} has been disconnected')
        return "Auth: 0"
    else:
        app.logger.info(f'client {mac_n} is authenticated')
        return "Auth: 1"

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
        month_limit = 1000000000  # 1 GB monthly limit
        
        # Simulate device data usage
        device = {
            "mac": session.get("mac", "00:00:00:00"),
            "free_data": session.get("free_data", 10000000),  # Simulate 10 MB used
            "month_data": session.get("month_data", 200000000),  # Simulate 200 MB used
        }

        # Format the used data and remaining data limits
        daily_used = format_limit(device["free_data"] / 1000000)
        monthly_used = format_limit(device["month_data"] / 1000000)
        day_rem = daily_limit - device["free_data"] if daily_limit - device["free_data"] >= 0 else 0
        month_rem = month_limit - device["month_data"] if month_limit - device["month_data"] >= 0 else 0
        daily_remaining = format_limit(day_rem / 1000000)
        monthly_remaining = format_limit(month_rem / 1000000)
    
    # Format limits for display
    ddd_limit = format_limit(daily_limit / 1000000)
    mmm_limit = format_limit(month_limit / 1000000)
    
    # Simulate fetching announcements (could be hardcoded or from another service)
    announcements = ["Welcome to Apollo Wi-Fi!", "Service maintenance on the 15th."]

    # Displays the time elapsed since user login
    if 'logged_in' in session:
        login_time = session['login_time']
        logged_in_duration = datetime.datetime.now(timezone) - login_time
        time_remaining = datetime.timedelta(minutes=1) - logged_in_duration
        if logged_in_duration > datetime.timedelta(minutes=1):
            return redirect(url_for('logout'))

    return render_template( 
        'portal.html',
        daily_used=daily_used,
        monthly_used=monthly_used,
        time_used=logged_in_duration,
        daily_remaining=daily_remaining,
        monthly_remaining=monthly_remaining,
        time_remaining=time_remaining,
        daily_limit=ddd_limit,
        monthly_limit=mmm_limit,
        time_limit='1 minute',
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

    app.logger.info('user has been logged out...')
    flash("You have been logged out.")
    return render_template('logout.html', message="You have been logged out.")

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)