import sys
sys.path.append("../Spartan")
import os
import time
import argparse
from tabulate import tabulate
from datetime import datetime
from Spartan.lib.script_execute import ScriptExecute
from Spartan.lib.port_scan import Scanner
from Spartan.lib.helpers.helpers import color, Port
from art import tprint


def app():
    parser = argparse.ArgumentParser(
        description=" * " + color.ITALIC + "hacking music in background" + color.STOP_ITALIC + " *", add_help=False)
    parser.add_argument("--help", action="store_true", help="show this reference")
    parser.add_argument("--host", "-h", type=str, help="ip address")
    parser.add_argument("--port", "-p", type=str, help="port to scan if all print 'a' if range print example: 1-20, "
                                                       "or if just want to check top 1000 tcp port just print 'd' ")
    parser.add_argument("--mode", type=str, help="scan mode")
    parser.add_argument("--only_known_service", help="return only port with known services", action='store_true')
    parser.add_argument("--output", help="dump scan result to text file", action='store_true')
    parser.add_argument("--script", help="path to your script", action='append')
    parser.add_argument("--timeout", type=float, help="timeout for scanner")
    parser.add_argument("--basic", help="return only scan result", action="store_true")

    args = parser.parse_args()
    if len(sys.argv) == 1 or args.help:
        parser.print_help()
        sys.exit(1)

    hostname = args.host
    port = "a"
    os_detecion = None
    port_mode = ""
    mode = "no mode selected"
    scripts = args.script
    range_start = 0
    range_end = 0
    if args.port == "a":
        port_mode = "all ports"
        mode = "all ports"
    # elif args.port == "d":
    #     port = Port.top_ports
    #     port_mode = "top port"
    #     # mode = "most common ports"
    # elif args.port.find("-") != -1:
    #     ports = args.port.split("-")
    #     range_start = ports[0]
    #     range_end = ports[1]
    #     port_mode = "range ports"
    #     mode = f"range between {ports[0]} {ports[1]}"
    #     port = [i for i in range(int(ports[0]), int(ports[1]))]
    else:
        port = int(args.port)
        port_mode = f"single port"
        mode = f"single port - {port}"
    if args.basic is False:
        tprint("CyberSpartan")
        print(color.ITALIC + "\t With great power comes great responsibility \n" + color.STOP_ITALIC)
        print("v0.1.1 created by " + color.BOLD + "dannyx-hub\n" + color.END)
        print("=" * 50)
        print(f"Spartan start checks ports on " + color.BOLD + f"{hostname}" + color.END)
        print("Date: {} ".format(datetime.today().strftime("%Y-%m-%d %H:%M:%S")))
        print(
            f"Scanner options: \n" + color.BOLD + "port: " + color.END + f"{mode}" + color.BOLD + "\nscripts" + color.END + f": {scripts}")
        print("=" * 50)
    if port:
        if port_mode == "all ports":
            print(
                "\n[?] " + color.YELLOW + "Warning" + color.END + " selected options may increase the scanning time [?]\n")
        timer = time.perf_counter()
        scan = Scanner(target=hostname, mode=port_mode, port=port, range_start=range_start, range_end=range_end)
        result = scan.start_scan()
        stop = time.perf_counter()
        print(color.GREEN + "\nResult for {}:".format(hostname) + color.END)
        print(f"found: {len(result)}")
        header = [color.BOLD + 'TYPE', 'PORT', 'STATUS', 'SERVICE' + color.END]
        table_data = []
        if result:
            for port, info in result.items():
                table_data.append(['TCP', info['port'], info['state'], info['service']])
            print("\n" + tabulate(table_data, headers=header, tablefmt="plain"))
            print("\nProgram end in: " + color.BOLD + f"{round(stop - timer, 2)}" + color.END + "s")

            if args.output:
                outfile_name = f"{hostname}_output.txt"
                with open(outfile_name, "w") as outfile:
                    scan_data = "\nDate: {} \n".format(datetime.today().strftime("%Y-%m-%d %H:%M:%S"))
                    banner = f"\nScanner options: \n" + color.BOLD + "port: " + color.END + f" {port_mode}\n" + color.BOLD + f"scan mode: " + color.END + f"{mode}\n"
                    outfile.writelines("=" * 50)
                    outfile.writelines(scan_data)
                    outfile.writelines(banner)
                    outfile.writelines("=" * 50 + "\n")
                    outfile.writelines(tabulate(table_data, headers=header, tablefmt="plain"))
            if args.script:
                if args.basic is False:
                    print("\n" + "=" * 50)
                    print("Spartan execute\n{}".format("\n".join(args.script)))
                    print("=" * 50)
                for script in args.script:
                    if script == os.path.basename(script):
                        full_path = os.path.join(os.path.dirname(__file__), "scripts", script)
                    else:
                        full_path = script
                    s = ScriptExecute(full_path, hostname, result)
                    s.execute()


        else:
            print(color.RED + "Result for {}: no open ports founds".format(hostname) + color.END)


if __name__ == "__main__":
    app()
