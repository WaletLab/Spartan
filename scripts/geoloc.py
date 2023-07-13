import requests
import json
from lib.helpers.helpers import color

if host:
    response = requests.get('http://ip-api.com/json/{}'.format(host))
    if response:
        res_dict = json.loads(response.content)
        print(color.BOLD+color.GREEN+"Geolocalization results:\n"+color.END)
        try:
            for k,v in enumerate(res_dict):
                print(color.BOLD+str(v)+color.END + ": " + str(res_dict[v]))
        except Exception as e:
            print(e)
else:
    print("no host selected")