import typer
from typing import Optional, List
from art import tprint
from Spartan.lib.helpers.helpers import color
from tabulate import tabulate
from Spartan.lib.port_scan import Scanner

app = typer.Typer()
def banner():
    tprint("CyberSpartan")
    print(color.ITALIC + "\t With great power comes great responsibility \n" + color.STOP_ITALIC)
    print("v0.1.3 created by " + color.BOLD + "dannyx-hub\n" + color.END)
def print_result(result):
    table_data = []
    header = [color.BOLD + 'TYPE', 'PORT', 'STATUS', 'SERVICE' + color.END]
    if result:
        for port, info in result.items():
            table_data.append(['TCP', info['port'], info['state'], info['service']])
        print("\n" + tabulate(table_data, headers=header, tablefmt="plain"))
@app.command()
def main(
    host: str,
    port: str,
):
    sc = Scanner(target=host, mode=port)
    result = sc.start_scan()
    if result:
        print_result(result)

if __name__ == "__main__":
    banner()
    typer.run(main)