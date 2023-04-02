from art import tprint
from helpers import color
import sys
import time
import argparse
from tabulate import tabulate
from port_scan import Scanner
debug = False
if debug is not True:
    tprint("Spartan")
    print(color.ITALIC + "\t We make shit safe again \n" + color.STOP_ITALIC)
    print("v0.0.2 created by " + color.BOLD + "dannyx-hub\n" + color.END)
parser = argparse.ArgumentParser(description="Tools to beat pussy scanners")
parser.add_argument("--host", type=str, help="ip address")
parser.add_argument("--port", type=str, help="port to scan if all print -a if range print example: 1-20")
parser.add_argument("--mode", type=str, help="scan mode")
parser.add_argument("--only_known_service", help="return only port with known services", action='store_true')
args = parser.parse_args()

sc = Scanner()
hostname = args.host
port = args.port
port_range = None
udp = None

# scan
print("*" * 50)
print(f"\tPort Scanner \nSpartan start to check ports on {hostname}")
print("*" * 50)
if args.mode == "u":
    print(" [*] udp mode activate [*] ")
    udp = True
if args.port == "a":
    print(" [*] beat some rustscan mode activate [*] ")
    port = None
else:
    if args.port.find("-") != -1:
        port = None
        ports = args.port.split("-")
        port_range = {"start": int(ports[0]), "stop": int(ports[1])}
        print(port_range)
    else:
        port = int(args.port)
result = sc.scan(hostname=hostname, port=port, port_range=port_range, udp=udp)
if result:
    print(color.GREEN + "Result for {}:".format(hostname) + color.END)
    print(f"found: {len(result)}")
    header = ['TYPE', 'PORT', 'STATUS', 'SERVICE', 'INFO']
    if args.only_known_service:
        table_data = [[x['type'], x['port'], x['status'], x['service'], x['info']]
                      for x in result if x['service'] is not None]
    else:
        table_data = [[x['type'], x['port'], x['status'], x['service'], x['info']] for x in result]
    print(tabulate(table_data, headers=header))
else:
    print(color.RED + "Result for {}: no open ports founds".format(hostname) + color.END)
print("\nProgram end in: " + color.BOLD + "{}".format(time.process_time()) + color.END)
sys.exit(0)
