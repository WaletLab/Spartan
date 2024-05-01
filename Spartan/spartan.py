import typer
from rich.progress import track
import time
import datetime
from art import tprint
# from lib.helpers import helpers
from lib.helpers.helpers import MessageType, print_banner, port_mode_parser, params_table

app = typer.Typer()
msg = MessageType()
# TODO mody do skanowania dajemy w command


@app.command(name="tcp", help="TCP SYN scan")
def single_port(host: str = typer.Option(help="target IP"),
                port: str = typer.Option(
                    help="just fucking port why need more"),
                retry_timeout: int = typer.Option(default=1, help="retry timeout")):

    msg.info("TCP SYN scan stared!")
    total = 0
    for value in track(range(100), description="Processing..."):
        # Fake processing time
        time.sleep(0.01)
        total += 1
    msg.success("Done!")
    msg.success(f"Results for {host}:")


@app.command(name="all_ports", help="scanning all TCP ports.")
def all_ports(host: str = typer.Option(help="target IP")):
    msg.info("all")


if __name__ == "__main__":
    print_banner()
    app()
