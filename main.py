from art import tprint
from tqdm import tqdm

from helpers import color, Port
import sys
import time
import argparse
from tabulate import tabulate
from port_scan import Scanner

debug = False
if debug is not True:
    tprint("Spartan")
    print(color.ITALIC + "\t With great power comes great responsibility \n" + color.STOP_ITALIC)
    print("v0.0.3 created by " + color.BOLD + "dannyx-hub\n" + color.END)
parser = argparse.ArgumentParser(description=" * "+color.ITALIC+"hacking music in background"+color.STOP_ITALIC+" *")
parser.add_argument("--host", type=str, help="ip address")
parser.add_argument("--port", type=str, help="port to scan if all print -a if range print example: 1-20")
parser.add_argument("--mode", type=str, help="scan mode")
parser.add_argument("--only_known_service", help="return only port with known services", action='store_true')
parser.add_argument("--output", help="dump scan result to text file")
args = parser.parse_args()
if len(sys.argv) == 1:
    # parser.print_usage()
    parser.print_help()
    sys.exit(1)
hostname = args.host
port = None
result = None
os_detection = None
# scan
print("*" * 50)
print(f"\tPort Scanner \nSpartan start to check ports on {hostname}")
print("*" * 50)
if args.mode == "u":
    print(" [*] udp mode activate [*] ")
    udp = True
elif args.mode == "os":
    print("[*] os detection activate [*]")
    os_detection = True
if args.port == "a":
    print(" [*] all ports [*] ")
    lst = [p for p in range(1, 65355 + 1)]
    port = Port.split_port_lists(lst, 1100)
elif args.port == "d":
    lst = Port.top_1000
    port = [lst]

else:
    if args.port.find("-") != -1:
        ports = args.port.split("-")
        lst = [p for p in range(int(ports[0]), int(ports[1]))]
        if len(lst) > 1000:
            port = Port.split_port_lists(lst, 10)
        else:
            port = [lst]

    else:
        port = [[int(args.port)]]
if port:
    if args.port == "a":
        timeout = 2.9
    else:
        timeout = 0.5
    timer = time.perf_counter()
    result = Scanner(hostname, port, timeout)
    result.execute()
    # for p in tqdm(range(len(port)), dynamic_ncols=True):
    #     result = Scanner(hostname, port[p]).execute()
        # tqdm().update()
    stop = time.perf_counter()
if result.scan_list:
    print(color.GREEN + "Result for {}:".format(hostname) + color.END)
    print(f"found: {len(result.scan_list)}")
    if os_detection:
        header = [color.BOLD+'TYPE', 'PORT', 'STATUS', 'SERVICE', 'INFO'+color.END]
    else:
        header = [color.BOLD+'TYPE', 'PORT', 'STATUS', 'SERVICE'+color.END]
    if args.only_known_service:
        # TODO zbieranie odpowiedzi moze niech bedzie oddzielnym trybem?
        if os_detection:
            table_data = [[x['type'], x['port'], x['status'], x['service'], x['info']] for x in result.scan_list if x['service'] is not None]
        else:
            table_data = [[x['type'], x['port'], x['status'], x['service']] for x in result.scan_list if x['service'] is not None]
    else:
        if os_detection:
            table_data = [[x['type'], x['port'], x['status'], x['service'], x['info']] for x in result.scan_list]
        else:
            table_data = [[x['type'], x['port'], x['status'], x['service']] for x in result.scan_list]
    print(tabulate(table_data, headers=header, tablefmt="plain"))
    if args.output:
        with open(args.output, "a") as outfile:
            outfile.writelines(tabulate(table_data, headers=header, tablefmt="plain"))
else:
    print(color.RED + "Result for {}: no open ports founds".format(hostname) + color.END)
print("\nProgram end in: " + color.BOLD + "{}".format(round(stop - timer, 2)) + color.END+"s")
sys.exit(0)
