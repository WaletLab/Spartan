import os
import asyncio
import sys
import typer
import datetime
from functools import wraps
from lib.newest_scanner import Scanner, ScanType, PortStatus
from lib.helpers.helpers import (MessageType, print_banner, print_scanner_options, port_mode_parser, return_table_result,
                                 return_result_to_file, return_script_result, return_script_list, get_filter_value, HelpMsg)

app = typer.Typer()
msg = MessageType()
state = {"basic": False}

async def execute_scan(type,host,port,retry_timeout,output,script,filter):
    scan_type = {
        "TCP SYN": ScanType.TCP_SYN,
        "UDP": ScanType.UDP,
    }
    if state['basic'] is False:
        print_scanner_options(datetime.datetime.today().strftime(
            "%Y-%m-%d %H:%M"), type, host, port, filter, retry_timeout)
        filter = get_filter_value(filter)
        if filter is False:
            msg.error("Wrong filter! Return to default")
            filter = PortStatus.OPEN
    with Scanner(host=host, pool_size=256, rtt_timeout=retry_timeout) as scn:
        msg.info(f"{type} scan stared!")
        result = await scn.scan(method=scan_type[type], ports=port_mode_parser(port))
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
def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapper
@app.command(name="scripts", help="List of avalible default scripts")
def script_lst():
    return_script_list()

@app.command(name="udp")
@coro
async def udp_scan(
    host: str = typer.Option(default="", help=HelpMsg.host),
    port: str = typer.Option(default="d", help=HelpMsg.port),
    retry_timeout: int = typer.Option(default=1, help=HelpMsg.retry_timeout),
    output: bool = typer.Option(default=False, help=HelpMsg.output),
    script: str = typer.Option(default=None, help=HelpMsg.script),
    filter: str = typer.Option(default="open", help=HelpMsg.filter)
):
    await execute_scan("UDP", host, port, retry_timeout, output, script, filter)

@app.command(name="syn")
@coro
async def tcp_syn_scan(
    host: str = typer.Option(default="", help=HelpMsg.host),
    port: str = typer.Option(default="d", help=HelpMsg.port),
    retry_timeout: int = typer.Option(default=1, help=HelpMsg.retry_timeout),
    output: bool = typer.Option(default=False, help=HelpMsg.output),
    script: str = typer.Option(default=None, help=HelpMsg.script),
    filter: str = typer.Option(default="open", help=HelpMsg.filter)
):
    await execute_scan("TCP SYN", host, port, retry_timeout, output, script, filter)

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
