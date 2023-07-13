from art import tprint
from lib.helpers.helpers import color, Port
import sys
import os
import time
import argparse
import asyncio
from tqdm import tqdm
from tabulate import tabulate
from lib.port_scan import Scanner
from datetime import datetime
from lib.script_execute import ScriptExecute

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

def app():
    parser = argparse.ArgumentParser(description=" * "+color.ITALIC+"hacking music in background"+color.STOP_ITALIC+" *", add_help=False)
    parser.add_argument("--help", action="store_true", help="show this reference")
    parser.add_argument("--host", "-h", type=str, help="ip address")
    parser.add_argument("--port", "-p", type=str, help="port to scan if all print 'a' if range print example: 1-20, or if just want to check top 1000 tcp port just print 'd' ")
    parser.add_argument("--mode", type=str, help="scan mode")
    parser.add_argument("--only_known_service", help="return only port with known services", action='store_true')
    parser.add_argument("--output", help="dump scan result to text file", action='store_true')
    parser.add_argument("--script",help="path to your script", action='append')
    parser.add_argument("--timeout",type=float, help="timeout for scanner")
    parser.add_argument("--basic", help="return only scan result",action="store_true")

    args = parser.parse_args()
    if len(sys.argv) == 1 or args.help:
        parser.print_help()
        sys.exit(1)
    hostname = args.host
    port = None
    result = None
    os_detection = False
    port_mode = ""
    mode = "no mode selected"
    scripts = args.script
    if args.mode == "u":
        mode = "udp scan"
        udp = True
    elif args.mode == "os":
        mode = "os detection"
        os_detection = True
    if args.port == "a":
        port_mode = "all ports"
        lst = [p for p in range(1, 65355 + 1)]
        port = Port.split_port_lists(lst, 500)
    elif args.port == "d":
        port_mode = "top used ports"
        lst = Port.top_ports
        port = [lst]

    else:
        if args.port.find("-") != -1:
            ports = args.port.split("-")
            port_mode = "range between {}-{}".format(ports[0],ports[1])
            lst = [p for p in range(int(ports[0]), int(ports[1]))]
            if len(lst) > 1000:
                port = Port.split_port_lists(lst, 10)
            else:
                port = [lst]

        else:
            port = [[int(args.port)]]
            port_mode = "single port {}".format(args.port)
    if args.basic is False:
        tprint("Spartan")
        print(color.ITALIC + "\t With great power comes great responsibility \n" + color.STOP_ITALIC)
        print("v0.0.6 created by " + color.BOLD + "dannyx-hub\n" + color.END)
        print("=" * 50)
        print(f"Spartan start checks ports on "+color.BOLD+f"{hostname}"+color.END)
        print("Date: {} ".format(datetime.today().strftime("%Y-%m-%d %H:%M:%S")))
        print(f"Scanner options: \n"+color.BOLD+"port: "+color.END+f" {port_mode}\n"+color.BOLD+f"scan mode: "+color.END+f"{mode}"+color.BOLD+"\nscripts"+color.END+f": {scripts}")
        print("=" * 50)
    if port:
        if args.port == "a" or args.mode == "os":
            print("\n[?] "+color.YELLOW+"Warning"+color.END+" selected options may increase the scanning time [?]\n")
            timeout = 2.9
        else:
            timeout = 0.5

        if args.mode == "os":
            print("\n"+color.BLUE+"Info:"+color.END+" os scan works only with this ports:\n21,22,80,443,8080\n")
        timer = time.perf_counter()
        result = []
        if args.port == "a":
            result = []
            for x in tqdm(port):
                res = Scanner(hostname,[x],timeout,os_detection)
                res.execute()
                if len(res.scan_list) !=0:
                    
                    result.extend(res.scan_list)
                
        else:
            res = Scanner(hostname, port, timeout,os_detection)
            res.execute()
            if len(res.scan_list) !=0:
                    result.extend(res.scan_list)
        stop = time.perf_counter()
    if result:
        print(color.GREEN + "\nResult for {}:".format(hostname) + color.END)
        print(f"found: {len(result)}")
        if os_detection:
            header = [color.BOLD+'TYPE', 'PORT', 'STATUS', 'SERVICE', 'INFO'+color.END]
        else:
            header = [color.BOLD+'TYPE', 'PORT', 'STATUS', 'SERVICE'+color.END]
        if args.only_known_service:
            if os_detection:
                table_data = [[x['type'], x['port'], x['status'], x['service'], x['info']] for x in result if x['service'] is not None]
            else:
                table_data = [[x['type'], x['port'], x['status'], x['service']] for x in result if x['service'] is not None]
        else:
            if os_detection:
                table_data = [[x['type'], x['port'], x['status'], x['service'], x['info']] for x in result]
            else:
                table_data = [[x['type'], x['port'], x['status'], x['service']] for x in result]
        print("\n"+tabulate(table_data, headers=header, tablefmt="plain"))
        if args.output: 
            outfile_name = f"{hostname}_output.txt"
            with open(outfile_name, "w") as outfile:
                scan_data = "\nDate: {} \n".format(datetime.today().strftime("%Y-%m-%d %H:%M:%S"))
                banner = f"\nScanner options: \n"+color.BOLD+"port: "+color.END+f" {port_mode}\n"+color.BOLD+f"scan mode: "+color.END+f"{mode}\n"
                outfile.writelines("="*50)
                outfile.writelines(scan_data)
                outfile.writelines(banner)
                outfile.writelines("="*50+"\n")
                outfile.writelines(tabulate(table_data, headers=header, tablefmt="plain"))
        if args.script:
            if args.basic is False:
                print("\n"+"="*50)
                print("Spartan execute\n{}".format("\n".join(args.script)))
                print("="*50)
            for script in args.script:
                if script == os.path.basename(script):
                    full_path = os.path.join(os.path.dirname(__file__), "scripts", script)
                else:
                    full_path = script
                s = ScriptExecute(full_path,hostname,result)
                s.execute()
    else:
        print(color.RED + "Result for {}: no open ports founds".format(hostname) + color.END)
    print("\nProgram end in: " + color.BOLD + "{}".format(round(stop - timer, 2)) + color.END+"s")
    sys.exit(0)

if __name__ == "__main__":
    app()