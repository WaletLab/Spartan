from art import tprint
from helpers import color
import sys
import time
from port_scan import Scanner



tprint("Welcome to Spartan")
print(color.ITALIC+"\t We make shit safe again \n"+color.STOP_ITALIC)
print("v0.0.1 created by "+color.BOLD+"dannyx-hub\n"+color.END)
if len(sys.argv) <= 1:
    print(color.RED+"ERROR:"+color.END+" no options selected - write --help or -h to check all options")
else:
    sys_len = len(sys.argv)
    if sys.argv[1] == "--scanner":
        # TODO port_range jest do przerobienia bo teraz ify sie pierdola
        sc = Scanner()
        port = None
        port_range = None
        print("*" * 30)
        print("\tPort Scanner")
        print("*" * 30)
        hostname = sys.argv[2]
        if sys_len > 3:
            if sys.argv[3] == "-p":
                port = int(sys.argv[4])
            elif sys.argv[3] == "-pr":
                port_range = {'start': int(sys.argv[4]), "stop": int(sys.argv[5])}

        result = sc.scan(hostname=hostname, port=port, port_range=port_range)
        if result:
            print(color.GREEN + "Result for {}:".format(hostname) + color.END)
            print("\t PORT  STATUS")
            for x in result:
                print("\t  {}  {}".format(x['port'], x['status']))
        else:
            print(color.RED + "Result for {}: no open ports founds".format(hostname) + color.END)

    elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("""\t
        --scanner or -p: port scaner
        --services or -s: service scanner
        --shodan or -d: shodan info getters
        --remote or -r: remote shell exploits
        --help or -h: help
        """)
    else:
        print(color.RED+"ERROR:"+color.END+" invalid command - write --help or -h to check all options")

    print("\nProgram end in: "+color.BOLD+"{}".format(time.process_time())+color.END)
    sys.exit("done")