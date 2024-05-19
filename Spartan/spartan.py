import typer
import time
import datetime
from art import tprint
from lib.new_scanner import Scanner, ScanType, PortStatus
from lib.helpers.helpers import MessageType, print_banner, print_scanner_options, port_mode_parser, return_table_result, return_result_to_file, return_script_result

app = typer.Typer()
msg = MessageType()
state = {"basic": False}
# TODO mody do skanowania dajemy w command
# TODO

@app.command(name="scripts", help="List of avalible default scripts")
def script_lst():
    return return_script_list

@app.command(name="tcp", help="TCP SYN scan")
def tcp_syn_scan(host: str = typer.Option(help="target IP"),
                 port: str = typer.Option(
    default="d", help="just fucking port why need more"),
    retry_timeout: int = typer.Option(
    default=1, help="retry timeout"),
    output: bool = typer.Option(False, help="Save output to file"),
    script: str = typer.Option("", help="Path to script, default scripts ")
):
    sc = Scanner(host, pool_size=128)
    if state['basic'] is False:
        print_scanner_options(datetime.datetime.today().strftime(
            "%Y-%m-%d %H:%M"), "TCP SYN Scan", host, port, retry_timeout)
    msg.info("TCP SYN scan stared!")
    ports = port_mode_parser(port)
    result = sc.scan(ScanType.TCP_SYN, ports)
    result = [x for x in result if x.status != PortStatus.CLOSED]
    msg.success("Done!")
    if len(result) != 0:
        msg.success(f"Results for {host}: \n")
        return_table_result(result)
    else:
        msg.warning("No open ports found!")
    if output:
        return_result_to_file(host, result)


@app.command(name="udp", help="UDP scan")
def udp_scan(host: str = typer.Option(help="target IP"),
             port: str = typer.Option(help="just fucking port why need more"),
             retry_timeout: int = typer.Option(default=1, help="retry timeout")
             ):
    if state["basic"] is False:
        print_scanner_options(datetime.datetime.today().strftime(
            "%Y-%m-%d %H:%M"), "UDP scan", host, port, retry_timeout)
    msg.info("UDP scan started!")
    # TODO tutaj puszczamy skan
    msg.success("Done!")
    msg.success(f"Results for {host}:")


@app.callback()
def banner(basic: bool = False):
    if basic is False:
        print_banner()
    state["basic"] = basic


if __name__ == "__main__":
    app()
