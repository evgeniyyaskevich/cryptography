import json
import uuid
import os
from base64 import b64decode, b64encode
import rsa
import struct
from time import time
from flask import Flask, request
from aes import encrypt_file, decrypt_file

app = Flask(__name__)

db = {
    'admin': {
        'password': 'admin'
    },
    'Bob': {
        'password': 'Bob'
    },
    'Alice': {
        'password': 'Alice'
    }
}

SESSION_KEY_EXPIRATION_TIME = 60 #seconds
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
APP_TEXTS = os.path.join(APP_ROOT, 'texts')

def is_key_expired(created_at):
    return time() - created_at > SESSION_KEY_EXPIRATION_TIME

@app.route('/login', methods = ['POST'])
def login():
    body = request.get_json()
    print('Request body:', body)
    
    username, password = body['username'], body['password']
    if db.get(username, {}).get('password') != password:
        return json.dumps({'result_msg': "Invalid username or password"}), 401
    try:
        pub_key = rsa.PublicKey(int(body['n']), int(body['e']))
    except:
        return json.dumps({'result_msg': 'Error during parsing public key.'}), 400
    
    session_key = rsa.randnum.read_random_bits(128)
    print('Session key:', session_key)

    cipher = rsa.encrypt(session_key, pub_key)
    cipher_str = b64encode(cipher).decode('utf8')

    db[username]['session_key'] = session_key
    db[username]['session_key_created_at'] = time()
    
    return json.dumps({'session_key': cipher_str}), 200

@app.route('/read', methods = ['POST'])
def read():
    body = request.get_json()
    print('Request body:', body)

    user = db.get(body['username'], {})
    if is_user_session_expired(user):
        return json.dumps({'result_msg': 'Session key is not valid.'}), 401
    
    key = user.get('session_key')
    filename = body['filename']
    return encrypt_file(key, os.path.join(APP_TEXTS, filename)), 200

@app.route('/update', methods = ['POST'])
def update():
    body = request.get_json()
    print('Request body:', body)

    user = db.get(body['username'], {})
    if is_user_session_expired(user):
        return json.dumps({'result_msg': 'Session key is not valid.'}), 401

    key = user.get('session_key')
    filename = body['filename']
    json_k = ['cipher_text', 'nonce', 'tag']
    cipher_text, nonce, tag = [b64decode(body[item]) for item in json_k]

    try:   
        plain_text = decrypt_file(key, nonce, cipher_text, tag)
        with open(os.path.join(APP_TEXTS, filename), 'wb') as fout:
            fout.write(plain_text)
    except:
        return json.dumps({'result_msg': 'Something went wrong.'}), 400
    
    return json.dumps({'result_msg': "Nice! Thank you! Done!"}), 200

@app.route('/filelist', methods = ['POST'])
def filelist():
    body = request.get_json()
    print('Request body:', body)

    user = db.get(body['username'], {})
    if is_user_session_expired(user):
        return json.dumps({'result_msg': 'Session key is not valid.'}), 401

    files = [f for f in os.listdir(APP_TEXTS)]

    return json.dumps({'files': files}), 200

def is_user_session_expired(user):
    return not user.get('session_key') or is_key_expired(user.get('session_key_created_at'))

if __name__ == '__main__':
    app.run()
