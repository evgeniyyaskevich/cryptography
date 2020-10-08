import requests

response = requests.post('http://127.0.0.1:5000/login', data = {'n':'123', 'e': '5124'})
print(response)