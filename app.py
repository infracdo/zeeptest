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
    gw_id = request.args.get('gw_id', 'mpop9016MP')
    gw_sn = request.args.get('gw_sn', 'mpop9016MP')
    gw_address = request.args.get('gw_address', '1.2.3.4')
    gw_port = request.args.get('gw_port', '2060')
    ip = request.args.get('ip', '10.51.0.62')
    mac = request.args.get('mac', '58:fb:84:78:69:fa')
    apmac = request.args.get('apmac', '0074.9c65.8d2c')
    ssid = request.args.get('ssid', 'TEST PORTAL 2')
    vlanid = request.args.get('vlanid', '51')
    url = request.args.get('url', 'http://www.msftconnecttest.com/redirect')

    return render_template("index.html", gw_id=gw_id, gw_sn=gw_sn, gw_address=gw_address, 
                           gw_port=gw_port, ip=ip, mac=mac, apmac=apmac, ssid=ssid, 
                           vlanid=vlanid, url=url)

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
