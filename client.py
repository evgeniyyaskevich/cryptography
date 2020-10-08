import rsa
import base64
import requests

RSA_KEY_SIZE = 512
SERVER_ADDRESS = 'https://localhost:5000'

(pubkey, privkey) = rsa.newkeys(RSA_KEY_SIZE)
r = requests.post(SERVER_ADDRESS + '/login', 
    data={'n': pubkey['n'], 'e': pubkey['e'], 'username': 'Bob', 'password': '12345'})
print(r.json())
session_key = rsa.decrypt(base64.b64decode(r['session_key']), privkey).decode('utf8')
