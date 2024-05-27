import os
import asyncio
import sys
import typer
import datetime
from lib.newest_scanner import Scanner, ScanType, PortStatus
from lib.helpers.helpers import (MessageType, print_banner, print_scanner_options, port_mode_parser, return_table_result,
                                 return_result_to_file, return_script_result, return_script_list, get_filter_value)

app = typer.Typer()
msg = MessageType()
state = {"basic": False}
# TODO mody do skanowania dajemy w command
# TODO filtry po PortStatus

@app.command(name="scripts", help="List of avalible default scripts")
def script_lst():
    return_script_list()

@app.command(name="tcp", help="TCP SYN scan")
async def tcp_syn_scan(host: str = typer.Option(help="target IP"),
                 port: str = typer.Option(
    default="d", help="just fucking port why need more"),
    retry_timeout: int = typer.Option(
    default=1, help="retry timeout"),
    output: bool = typer.Option(False, help="Save output to file"),
    script: str = typer.Option(None, help="Path to script, default scripts "),
    filter: str = typer.Option(default="open", help="Filter to result. Default - open. Filters avalible: open, closed, "
                                                    "filtered, closed_or_open, awaiting ")
):
    with Scanner(host=host, pool_size=256, rtt_timeout=retry_timeout) as scn:
        msg.info("TCP SYN scan stared!")
        result = await scn.scan(method=ScanType.TCP_SYN, ports=port_mode_parser(port))
    if state['basic'] is False:
        print_scanner_options(datetime.datetime.today().strftime(
            "%Y-%m-%d %H:%M"), "TCP SYN Scan", host, port, retry_timeout)
    filter = get_filter_value(filter)
    if filter is False:
        msg.error("Wrong filter! Return to default")
        filter = PortStatus.OPEN
    result = [x for x in result.values() if x.status == filter]
    msg.success("Done!")
    if len(result) != 0:
        msg.success(f"Results for {host}: \n")
        return_table_result(result)
    else:
        msg.warning("No open ports found!")
    if output:
        return_result_to_file(host, result)
    if script:
        return_script_result(script, result, host)

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
    if os.geteuid() != 0:
        msg.error("need sudo to run this masterpiece")
        sys.exit(0)
    app()
