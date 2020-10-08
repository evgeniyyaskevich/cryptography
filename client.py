import rsa
import base64
import requests

RSA_KEY_SIZE = 512
SERVER_ADDRESS = 'http://localhost:5000'

(pubkey, privkey) = rsa.newkeys(RSA_KEY_SIZE)
r = requests.post(SERVER_ADDRESS + '/login', 
    json={'n': pubkey['n'], 'e': pubkey['e'], 'username': 'Bob', 'password': '12345'})
session_key = rsa.decrypt(base64.b64decode(r.json()['session_key'].encode('utf8')), privkey)
