import typer
import time
import datetime
from art import tprint
# from lib.helpers import helpers
from lib.helpers.helpers import MessageType, print_banner, print_scanner_options

app = typer.Typer()
msg = MessageType()
state = {"basic": False}
# TODO mody do skanowania dajemy w command


@app.command(name="tcp", help="TCP SYN scan")
def single_port(host: str = typer.Option(help="target IP"),
                port: str = typer.Option(
                    help="just fucking port why need more"),
                retry_timeout: int = typer.Option(
                    default=1, help="retry timeout"),
                ):
    if state['basic'] is False:
        print_scanner_options(datetime.datetime.today().strftime(
            "%Y-%m-%d %H:%M"), "TCP SYN Scan", host, port, retry_timeout)

    msg.info("TCP SYN scan stared!")
    msg.success("Done!")
    msg.success(f"Results for {host}:")


@app.command(name="all_ports", help="scanning all TCP ports.")
def all_ports(host: str = typer.Option(help="target IP")):
    msg.info("all")


@app.callback()
def banner(basic: bool = False):
    if basic is False:
        print_banner()
    state["basic"] = basic


if __name__ == "__main__":
    app()
