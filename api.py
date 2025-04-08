from flask import Blueprint, jsonify, request
from models import db, Account, Transaction, AuthLog, ClientSession, Package


api_blueprint = Blueprint('api', __name__)


@api_blueprint.get("/accounts")
def getAccountDetails():
    accounts = Account.query.all()

    result = [
        {
            'id': account.id,
            'uname': account.uname,
            'pword': account.pword,
            'total_incoming_packets': account.total_incoming_packets,
            'total_outgoing_packets': account.total_outgoing_packets,
            'last_active': account.last_active
        }
        for account in accounts
    ]

    return jsonify(result)

@api_blueprint.get("/transactions")
def getAccountTransactions():
    transactions = Transaction.query.all()

    result = [
        {
            'id': transaction.id,
            'acc_id': transaction.acc_id,
            'package_id': transaction.package_id,
            'vlanid': transaction.vlanid,
            'gw_id': transaction.gw_id,
            'gw_sn': transaction.gw_sn,
            'gw_address': transaction.gw_address,
            'gw_port': transaction.gw_port,
            'ssid': transaction.ssid,
            'apmac': transaction.apmac,
            'mac': transaction.mac,
            'device': transaction.device,
            'ip': transaction.ip,
            'token': transaction.token,
            'stage': transaction.stage,
            'total_incoming_packets': transaction.total_incoming_packets,
            'total_outgoing_packets': transaction.total_outgoing_packets,
            'created_on': transaction.created_on,
            'last_active': transaction.last_active
        }
        for transaction in transactions
    ]

    return jsonify(result)

@api_blueprint.get("/account-sessions")
def getAccountSessions():
    account_sessions = ClientSession.query.all()

    result = [
        {
            'id': acct_session.id,
            'client_id': acct_session.client_id,
            'package_id': acct_session.package_id,
            'limit_count': acct_session.limit_count,
            'limit_type': acct_session.limit_type,
            'counter': acct_session.counter,
            'incoming_packets': acct_session.incoming_packets,
            'outgoing_packets': acct_session.outgoing_packets,
            'created_on': acct_session.created_on,
            'last_modified': acct_session.last_modified
        }
        for acct_session in account_sessions
    ]

    return jsonify(result)

@api_blueprint.get("/packages")
def getPackages():
    packages = Package.query.all()

    result = [
        {
            'id': package.id,
            'title': package.title,
            'description': package.description,
            'limit_count': package.limit_count,
            'limit_type': package.limit_type,
            'package_type': package.package_type,
            'price': package.price,
            'validity': package.validity
        }
        for package in packages
    ]

    return jsonify(result)

@api_blueprint.get("/auth-logs")
def getAuthLogs():
    auth_logs = AuthLog.query.all()

    result = [
        {
            'id': auth_log.id,
            'uname': auth_log.uname,
            'mac': auth_log.mac,
            'gw_id': auth_log.gw_id,
            'stage': auth_log.stage,
            'date': auth_log.date
        }
        for auth_log in auth_logs
    ]

    return jsonify(result)