import requests
headers = {
  'Accept': 'application/json',
  'X-ZAP-API-Key': 'API_KEY'
}

r = requests.get('http://zap/JSON/localProxies/action/removeAdditionalProxy/', params={
  'address': 'string',  'port': '0'
}, headers = headers)

print (r.json)