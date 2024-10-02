from flask import Flask, render_template, request, redirect, url_for
import json

app = Flask(__name__)


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
    gw_id = request.args.get('gw_id', default='', type=str)
    gw_sn = request.args.get('gw_sn', default='', type=str)
    gw_address = request.args.get('gw_address', default='', type=str)
    gw_port = request.args.get('gw_port', default='', type=str)
    ip = request.args.get('ip', default='', type=str)
    mac = request.args.get('mac', default='', type=str)
    apmac = request.args.get('apmac', default='', type=str)
    ssid = request.args.get('ssid', default='', type=str)
    vlanid = request.args.get('vlanid', default='', type=str)
    

    return render_template("index.html", gw_id=gw_id, gw_sn=gw_sn, gw_address=gw_address, 
                           gw_port=gw_port, ip=ip, mac=mac, apmac=apmac, ssid=ssid, 
                           vlanid=vlanid)

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
