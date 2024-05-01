from rich import print, table
from art import tprint


class MessageType:
    def error(self, msg):
        print(f"[bold red]{msg}[/bold red]")

    def success(self, msg):
        print(f"[bold green]{msg}[/bold green]")

    def warning(self, msg):
        print(f"[bold yellow]{msg}[/bold yellow]")

    def info(self, msg):
        print(f"[bold blue]{msg}[/bold blue]")


def print_banner():
    tprint("Spartan")
    print("version: 2.0.0")
    print("[italic]created by WaletLab[/italic]\n")


def port_mode_parser(port):
    if port.find(":") != -1:
        port_range = port.split(":")
        return [x for x in range(int(port_range[0]), int(port_range[1])+1)]
    else:
        return port


def params_table(params):
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table()

    # Dodanie kolumn
    table.add_column("param")
    table.add_column("value")

    for param, value in params:
        table.add_row(param, value)

    console.print(table)
