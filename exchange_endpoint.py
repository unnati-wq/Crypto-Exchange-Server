from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
from algosdk import mnemonic
from algosdk.v2client import indexer
# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    log_obj = Log(message = msg)
    g.session.add(log_obj)
    g.session.commit(log_obj)
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    mnemonic_secret = "multiply airport suit ranch position album aspect citizen december popular alert rate carpet motion lottery they orchard infant sunny exotic pencil maple uniform ability vast"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    return algo_sk, algo_pk


def get_eth_keys():
    w3 = connect_to_eth()
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    w3.eth.account.enable_unaudited_hdwallet_features()
    mnemonic_secret = "island front adapt host govern cotton shy above grant panic north recipe"
    print("ETH MNEMONIC SECRET:",mnemonic_secret)
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key
    return eth_sk, eth_pk

def check_match_order(order):
    result = False
    if (order.sell_currency == 'Ethereum'):
        try:
            if(order.tx_id == None):
                return result 
            w3 = connect_to_eth()
            tx = w3.eth.get_transaction(order.tx_id)
            eth_sk,eth_pk = get_eth_keys()
            if(tx['value'] == order.sell_amount and tx['from'] == order.sender_pk and tx['to'] == eth_pk):
                result = True
        except Exception as e:
            print(traceback.format_exc())
            print(e)   
    if (order.sell_currency == 'Algorand'):
        try:
            acl = connect_to_algo("indexer")
            #acl = indexer.IndexerClient(indexer_token="", indexer_address="http://localhost:8980")
            tx = acl.search_transactions(txid=order.tx_id)
            a = tx['transactions']
            b = a[0]
            amount = b['payment-transaction']['amount']
            to = b['payment-transaction']['receiver']
            froms = b['sender']
            algo_sk,algo_pk = get_algo_keys()
            if(amount == order.sell_amount and froms == order.sender_pk and to == algo_pk):
                result = True
        except Exception as e:
            print(traceback.format_exc())
            print(e)

    return result

def create_dict(order, amount):
    tx_dict={}
    tx_dict['amount'] = amount
    tx_dict['platform'] = order.buy_currency
    tx_dict['receiver_pk'] = order.receiver_pk
    tx_dict['order_id'] = order.id
    tx_dict['tx_id'] = order.tx_id
    tx_dict['order'] = order
    return tx_dict

def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    result = False
    orders = g.session.query(Order).all() #Get all filled orders
    for existing_order in orders:
        match_order = existing_order
        if existing_order.filled == None:
            if existing_order.buy_currency == order.sell_currency:
                if existing_order.sell_currency == order.buy_currency:
                    if (order.sell_amount*existing_order.sell_amount >= existing_order.buy_amount*order.buy_amount):
                        match_order = existing_order
                        result = check_match_order(match_order)
                        if(result == False):
                            continue
                        timestamp = datetime.now()
                        match_order.filled, order.filled = timestamp, timestamp
                        match_order.counterparty_id = order.id
                        order.counterparty_id = match_order.id
                        g.session.commit()
                        if match_order.buy_amount > order.sell_amount:
                            order = Order( sender_pk=match_order.sender_pk,receiver_pk=match_order.receiver_pk, buy_currency=match_order.buy_currency, sell_currency=match_order.sell_currency, buy_amount=match_order.buy_amount - order.sell_amount, sell_amount=match_order.sell_amount - order.buy_amount, creator_id=match_order.id)
                            g.session.add(order)
                            g.session.commit()
                        if order.buy_amount >  match_order.sell_amount:
                            order = Order( sender_pk=order.sender_pk,receiver_pk=order.receiver_pk, buy_currency=order.buy_currency, sell_currency=order.sell_currency, buy_amount=order.buy_amount - match_order.sell_amount, sell_amount=order.sell_amount - match_order.buy_amount, creator_id=order.id )
                            g.session.add(order)
                            g.session.commit()
                        break;
    if match_order.buy_amount>=order.sell_amount:
        tx_dict = create_dict(match_order, order.sell_amount)
        txes.append(tx_dict)
    if match_order.buy_amount<order.sell_amount:
        tx_dict = create_dict(match_order, match_order.buy_amount)
        txes.append(tx_dict)
    if order.buy_amount>=match_order.sell_amount:
        tx_dict = create_dict(order, match_order.sell_amount)
        txes.append(tx_dict)
    if order.buy_amount<match_order.sell_amount:
        tx_dict = create_dict(order, order.buy_amount)
        txes.append(tx_dict)
    return txes
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    algo_tx_ids=send_tokens_algo(g.acl, algo_sk, algo_txes)
    eth_tx_ids=send_tokens_eth(g.w3, eth_sk, eth_txes)
    for algo in algo_txes:
        tx_obj = TX(platform=algo['platform'], receiver_pk=algo['receiver_pk'],order_id=algo['order_id'],order=algo['order'],tx_id=algo['tx_id'])
        g.session.add(tx_obj)
        g.session.commit()
    for eth in eth_txes:
        #eth_tx_id=send_tokens_eth(g.w3, eth_sk, eth)
        tx_obj = TX(platform=eth['platform'], receiver_pk=eth['receiver_pk'],order_id=eth['order_id'],order=eth['order'],tx_id=eth['tx_id'])
        g.session.add(tx_obj)
        g.session.commit()
""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            eth_sk,eth_pk = get_eth_keys()
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk,algo_pk = get_algo_keys()
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        try:
            sig = content['sig']
            payload = content['payload']
            msg = json.dumps(payload)
            pk = content['payload']['sender_pk']
            platform = content['payload']['platform']
            result = False
            if(platform == 'Ethereum'):
                eth_encoded_msg = eth_account.messages.encode_defunct(text=msg)
                if eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == pk:
                    result = True
        #Should only be true if signature validates
            if(platform == 'Algorand'):
                if algosdk.util.verify_bytes(msg.encode('utf-8'),sig,pk):
                    result = True
        except Exception as e:
            print(traceback.format_exc())
            print(e)
        # 2. Add the order to the table
        if result == False:
            return jsonify(False)
        txes =[]
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        if (payload['sell_currency'] == 'Ethereum'):
            try:
                w3 = connect_to_eth()
                tx = w3.eth.get_transaction(payload['tx_id'])
                eth_sk,eth_pk = get_eth_keys()
                if(tx['value'] == payload['sell_amount'] and tx['from'] == payload['sender_pk'] and tx['to'] == eth_pk):
                    order_obj = Order( sender_pk=pk,receiver_pk=content['payload']['receiver_pk'], buy_currency=content['payload']['buy_currency'], sell_currency=content['payload']['sell_currency'], buy_amount=content['payload']['buy_amount'], sell_amount=content['payload']['sell_amount'], signature=sig, tx_id=content['payload']['tx_id'] )
                    g.session.add(order_obj)
                    g.session.commit()
                    txes = fill_order(order_obj, txes)
                else:
                    log_message(content)
                    return jsonify(False)
            except Exception as e:
                print(traceback.format_exc())
                print(e)
                return jsonify(False)
        if (payload['sell_currency'] == 'Algorand'):
            try:
                acl = connect_to_algo("indexer")
                #acl = indexer.IndexerClient(indexer_token="", indexer_address="http://localhost:8980")
                tx = acl.search_transactions(txid=payload['tx_id'])
                print(json.dumps(tx['transactions']))
                a = tx['transactions']
                b = a[0]
                print(json.dumps(b))
                amount = b['payment-transaction']['amount']
                print(amount)
                to = b['payment-transaction']['receiver']
                print(to)
                froms = b['sender']
                print(froms)
                
            
                algo_sk,algo_pk = get_algo_keys()
                if(amount == payload['sell_amount'] and froms == payload['sender_pk'] and to == algo_pk):
                    order_obj = Order( sender_pk=pk,receiver_pk=content['payload']['receiver_pk'], buy_currency=content['payload']['buy_currency'], sell_currency=content['payload']['sell_currency'], buy_amount=content['payload']['buy_amount'], sell_amount=content['payload']['sell_amount'], signature=sig, tx_id=content['payload']['tx_id'] )
                    g.session.add(order_obj)
                    g.session.commit()
                    txes = fill_order(order_obj, txes)
                else:
                    log_message(content)
                    return jsonify(False)
            except Exception as e:
                print(traceback.format_exc())
                print(e)
                return jsonify(False)
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        
        # 4. Execute the transactions
        execute_txes(txes)
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
    # Same as before
    orders = g.session.query(Order).all()
    order_list =[]
    result ={}
    for order in orders:
        dict_order = {}
        dict_order['sender_pk'] = order.sender_pk
        dict_order['receiver_pk'] = order.receiver_pk
        dict_order['buy_currency'] = order.buy_currency
        dict_order['sell_currency'] = order.sell_currency
        dict_order['buy_amount'] = order.buy_amount
        dict_order['sell_amount'] = order.sell_amount
        dict_order['signature'] = order.signature
        order_list.append(dict_order)
    result['data'] = order_list
    return jsonify(result)
    

if __name__ == '__main__':
    app.run(port='5002')
