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


def print_scanner_options(date, mode, host, port, retry_timeout):
    print("\n[bold blue]Scanner Options: [/bold blue]")
    print(f"[bold]Date: [/bold] {date}\n[bold]Host: [/bold] {host}\n[bold]Mode: [/bold] {mode}\n[bold]Port: [/bold] {port}\n[bold]Retry timeout: [/bold] {retry_timeout}\n")


def port_mode_parser(port):
    if port.find(":") != -1:
        port_range = port.split(":")
        return [x for x in range(int(port_range[0]), int(port_range[1])+1)]
    else:
        return port
