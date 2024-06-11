import requests
import json
if host:
    response = requests.get('http://ip-api.com/json/{}'.format(host))
    if response:
        res_dict = json.loads(response.content)
        print("Geolocalization results:\n")
        try:
            for k,v in enumerate(res_dict):
                print(str(v)+ ": " + str(res_dict[v]))
        except Exception as e:
            print(e)
else:
    print("no host selected")




