from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

csrf = CSRFProtect(app)
app.secret_key = b'_5#y2L!.4Q8z\n\xec]/'


# <---------- ROUTES ---------->
@app.route('/wifidog/ping', strict_slashes=False)
@app.route('/ping', strict_slashes=False)
def ping():
    return "Pong"

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/wifidog/login/', methods = ['GET', 'POST'], strict_slashes=False)
@app.route('/login', methods = ['GET', 'POST'], strict_slashes=False)
def login():
    #token = session['token']

    session['gw_id'] = request.args.get('gw_id', default='', type=str)
    session ['gw_sn'] = request.args.get('gw_sn', default='', type=str)
    session ['gw_address'] = request.args.get('gw_address', default='', type=str)
    session ['gw_port'] = request.args.get('gw_port', default='', type=str)
    session ['ip'] = request.args.get('ip', default='', type=str)
    session ['mac'] = request.args.get('mac', default='', type=str)
    session ['apmac'] = request.args.get('apmac', default='', type=str)
    session ['ssid'] = request.args.get('ssid', default='', type=str)
    session ['vlanid'] = request.args.get('vlanid', default='', type=str)
    session['token'] = request.cookies.get('token')
    session['device'] = request.headers.get('User-Agent')
    session['logged_in'] = True

    return render_template("index.html")

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
