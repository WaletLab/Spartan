
# Spartan

Python-based TCP/UDP port scanner project. It is designed to scan a target system for open ports using either TCP or UDP protocols. 

The project is named after the Spartan warriors who were known for their swift and efficient tactics, reflecting the scanner's ability to quickly scan ports and efficiently report the results.
Spartan is designed to be fast and efficient. It uses multi-threading to speed up the scanning process and reduce the time it takes to scan a target system. The scanner also provides the option to save the results of the scan to a file for later analysis.

To achieve full speed, you don't need a Docker image. You simply download the program and it's ready to use.
Additionally, thanks to custom scripts, you can fully automate your work and turn reconnaissance into a pure pleasure!

## Demo




```    $ python spartan.py --host 81.143.78.93 --port d --script scripts/geoloc.py 
 ____                       _                 
/ ___|  _ __    __ _  _ __ | |_   __ _  _ __  
\___ \ | '_ \  / _` || '__|| __| / _` || '_ \ 
 ___) || |_) || (_| || |   | |_ | (_| || | | |
|____/ | .__/  \__,_||_|    \__| \__,_||_| |_|
       |_|                                    

     With great power comes great responsibility 

v0.0.5 created by dannyx-hub
==================================================
Spartan start checks ports on 127.0.0.1
Date: 2023-06-11 11:19:46 
Scanner options: 
port:  top used ports
scan mode: no mode selected
script_path: scripts/geoloc.py
==================================================

Result for 127.0.0.1:
found: 2

TYPE      PORT  STATUS    SERVICE
TCP       5005  OPEN      unknown
TCP         80  OPEN      http

==================================================
Spartan execute scripts/geoloc.py
==================================================
Geolocalization results:

status: success
country: Poland
countryCode: PL
region: PL
regionName: Poland
city: City of Wałrzych
zip: EC2V
lat: 514.5112354
lon: -04.0981412352
timezone: Europe/Wałbrzych
isp: WaletSec 
org: WaletSec org
as: Walet Telecomunications
query: 127.0.0.1

Program end in: 0.55s
```

## Features

- Scans all 65k ports in less than 3 seconds.
- Custom scripts support.
- Gui version(in progress)
- CMS detection

## Install
If you want to install Spartan, just clone the repository and install the required modules using pip (it is recommended to install it in a fresh virtual environment).
```sh
pip install -r requirements.txt
```
## Run
To run Spartan, simply type:
```sh
python spartan.py --host 127.0.0.1 --port d
```

## Contributing

As a contributor, you are welcome to make suggestions, report issues, or submit pull requests to improve the project. However, please keep in mind that the project is currently in development and does not have a stable version yet.

If you are interested in contributing, please reach out to us via email dannyx1543@gmail.com. We appreciate any help and support in making this project better. Thank you!


## Disclaimer

This tool is intended for legal and ethical use only. We do not condone or take any responsibility for any illegal activities carried out with this tool.

Please note that this product currently does not have a stable version and is still under development. As a result, the expected speeds and features are subject to change and may not be available at this time. Use at your own risk.

## Authors

- [@dannyx-hub](https://www.github.com/dannyx-hub)

