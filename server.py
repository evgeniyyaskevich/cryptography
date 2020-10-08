import json
import uuid
import os
import base64
import rsa
from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods = ['POST'])
def login():
    body = request.get_json(force=True)
    print('Request body:', body)
    #check user credentials here
    try:
        pub_key = rsa.PublicKey(int(body['n']), int(body['e']))
    except:
        return json.dumps({'result_msg': 'Error during parsing public key.'}), 400
    session_key = rsa.randnum.read_random_bits(128)
    print('Session key:', session_key)
    cipher = rsa.encrypt(session_key, pub_key)
    cipher_str = base64.b64encode(cipher).decode('utf8')
    return json.dumps({'session_key': cipher_str}), 200

if __name__ == '__main__':
    app.run()
    
    
