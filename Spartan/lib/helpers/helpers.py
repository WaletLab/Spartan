from rich import print as rprint
from rich.table import Table
from rich import box
from art import tprint
import datetime
import csv


class Port:
    top_ports = [1, 5, 9, 7, 11, 13, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 49, 53, 70, 79, 80, 81, 88, 106, 110, 111,
                 113, 119, 135, 139, 143, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554,
                 587,
                 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
                 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5001, 5003, 5004, 5005, 5050, 5060, 5101,
                 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6346, 6347,
                 6666, 6697, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 32768, 32769, 32770, 32771, 32772,
                 32773, 32774, 32775, 32776, 32777, 32778, 32779,
                 49152, 49153, 49154, 49155, 1028, 49157, 49156, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175,
                 49176, 32803, 4662, 4672, 3689, 3690, 4333, 49400, 49401, 49402, 49403, 49404, 49405, 49406, 49407,
                 49408, 49409, 49410, 49411, 49412, 49413, 49414, 49415, 49416, 49417, 49418, 49419, 49420, 5901, 49421,
                 49422, 10000, 49425, 49426, 49427, 49423, 49429, 49430, 49431, 49432, 49433, 49434, 49435, 49436,
                 49437, 49438, 49439, 49440, 49441, 49442, 49443, 49444, 49445, 49446, 49447, 49448, 49449, 49450,
                 49451, 49452, 49453, 49454, 49455, 49456, 49457, 49458, 49459, 49460, 7000, 49424, 49428, 7070, 5555,
                 6646, 7937]


class MessageType:
    def error(self, msg):
        rprint(f"[bold red]{msg}[/bold red]")

    def success(self, msg):
        rprint(f"[bold green]{msg}[/bold green]")

    def warning(self, msg):
        rprint(f"[bold yellow]{msg}[/bold yellow]")

    def info(self, msg):
        rprint(f"[bold blue]{msg}[/bold blue]")


def print_banner():
    tprint("Spartan")
    rprint("version: 2.0.0")
    rprint("[italic]created by WaletLab[/italic]\n")


def print_scanner_options(date, mode, host, port, retry_timeout):
    if port == "d":
        port = "default"
    elif port == "a":
        port = "al  l ports"
    rprint("\n[bold blue]Scanner Options: [/bold blue]")
    print(
        f"Date: {date}\nHost:  {host}\nMode:  {mode}\nPort:  {port}\nFilter:  {filter}\nRetry timeout:  {retry_timeout}\n")


def port_mode_parser(port):
    from lib.new_scanner import all_ports
    if port == "d":
        return Port.top_ports
    elif port == "a":
        return all_ports()
    else:
        if port.find(":") != -1:
            port_range = port.split(":")
            return [x for x in range(int(port_range[0]), int(port_range[1])+1)]
        else:
            return [int(port)]


def format_status(status):
    if status == "OPEN":
        return f"[green]{status}[/green]"
    elif status == "FILTERED":
        return f"[yellow]{status}[/yellow]"


def return_table_result(result):
    tb = Table(box=box.SIMPLE)
    tb.add_column("PORT")
    tb.add_column("STATUS")
    tb.add_column("DETAILS")
    for x in result:
        tb.add_row(str(x.port), format_status(x.status), x.detail)
    rprint(tb)


def return_result_to_file(host, result):
    outfile_name = f"{host}_output"
    with open(f"{outfile_name}.csv", "w", newline="") as outfile:
        writer = csv.writer(outfile, delimiter=';')
        writer.writerow(["PORT", "STATUS", "DETAILS"])
        writer.writerows([x.port, x.status, x.detail] for x in result)


def return_script_result(path, result, host):
    from lib.new_script import ScriptExec
    import os
    name = path.split("/")[-1]
    s = ScriptExec(name=name, host=host, result=result,
                   path=os.path.dirname(path))
    rprint(f"[blue bold]\nScript {name} result:[/blue bold]")
    s.run_exec()


def list_script_from_default(path):
    import os
    scripts = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".py"):
                scripts.append(file)
    return scripts
def return_script_list():
    script_list = list_script_from_default("./scripts")
    rprint("Default script list: ")
    for script in script_list:
        rprint(script)

def get_filter_value(filter):
    from lib.newest_scanner import PortStatus
    filters = {"open":PortStatus.OPEN,
               "closed":PortStatus.CLOSED,
               "filtered":PortStatus.FILTERED,
               "open_or_filtered":PortStatus.OPEN_OR_FILTERED,
               "awating":PortStatus.AWAITING}
    try:
        return filters[filter]
    except KeyError:
        return False