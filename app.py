from flask import Flask, request, session, render_template, redirect, flash, url_for
from flask_wtf.csrf import CSRFProtect
import datetime
from datetime import timedelta

app = Flask(__name__)
# Import configurations from .env file
app.config.from_object("config")

csrf = CSRFProtect(app)

# Temporary CSRF token for authentication
STATIC_TOKEN = "3b1f1e2f55c34c5b9f8c4e1a7b83e4d0"

# Encrypt the password submitted from form
def encryptPass(password):
    return password[::-1]

# For future purposes in setting limitations
def getLimit(gw_id, user_id, type_, default_limit):
    return default_limit

# <-------------------- LOGIN ROUTE --------------------->
@app.route('/wifidog/login/', methods=['GET', 'POST'], strict_slashes=False)
@app.route('/login/', methods=['GET', 'POST'], strict_slashes=False)
def login():
    # For form submission
    if request.method == 'POST':
        uname = request.form.get('uname')
        pword = encryptPass(request.form.get('pword'))
        package = request.form.get('package')
        token= session.get('token', STATIC_TOKEN)

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

            # Check if redirected to access point
            app.logger.info(f"Redirecting to: http://{trans['gw_address']}:{trans['gw_port']}/wifidog/auth?token={trans['token']}")

            # Redirect to the access point with token (Gateway Address: 1.2.3.4, Port: 2060)
            return redirect(f"http://{trans['gw_address']}:{trans['gw_port']}/wifidog/auth?token={trans['token']}", code=302)
        
    else:
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
        session['token'] = STATIC_TOKEN
        session['device'] = request.headers.get('User-Agent')
        session['logged_in'] = True
        
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
    token_n = request.args.get('token', default='', type=str)
    stage_n = request.args.get('stage', default='', type=str)
    incoming_n = request.args.get('incoming', default=0, type=int)
    outgoing_n = request.args.get('outgoing', default=0, type=int)

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

    # Simulate limit retrievals
    daily_limit = 50000000  # 50 MB
    month_limit = 1000000000  # 1 GB
    octets = trans['octets']

    # Free Access Authentication
    if trans['package'] == "One-Click Login":
        # Simulate tracking usage
        new_record = incoming_n + outgoing_n
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

    # "Auth: 1" represents successful authentication, "Auth: 0" if not
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
    
    return render_template(
        'portal.html',
        daily_used=daily_used,
        monthly_used=monthly_used,
        daily_remaining=daily_remaining,
        monthly_remaining=monthly_remaining,
        daily_limit=ddd_limit,
        monthly_limit=mmm_limit,
        announcements=announcements,
        display_type=display_type,
        path=path
    )

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
