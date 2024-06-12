import os
import socket
import asyncio
import sys
import typer
import time
import datetime
from rich.progress import Progress
from functools import wraps, partial
from lib.scanner import Scanner, ScanType, PortStatus, PortResult
from lib.helpers.helpers import (MessageType, print_banner, print_scanner_options, port_mode_parser,
                                 return_table_result,
                                 return_result_to_file, return_script_result, return_script_list, get_filter_value,
                                 HelpMsg)

app = typer.Typer()
msg = MessageType()
state = {"basic": False}

async def execute_scan(type, host, port, retry_timeout, output, script, filter, flag=None, packet_timeout=20):
    scanned = set()
    ports = port_mode_parser(port)
    def progress_cb(result: PortResult, progress: Progress, task):
        if result.port not in scanned:
            scanned.add(result.port)
        else:
            pass
        perc = (len(scanned) / len(ports)) * 100
        if perc > 100:
            return
        if perc > ((len(scanned)-1)/len(ports)) * 100:
            progress.update(task, completed=len(scanned))
    scan_type = {
        "TCP SYN": ScanType.TCP_SYN,
        "UDP": ScanType.UDP,
        "TCP FIN": ScanType.TCP_FIN,
        "TCP NULL": ScanType.TCP_NULL,
        "TCP XMAS": ScanType.TCP_XMAS
    }
    if state['basic'] is False:
        print_scanner_options(datetime.datetime.today().strftime(
            "%Y-%m-%d %H:%M"), type, host, port, filter, retry_timeout, packet_timeout)
        filter = get_filter_value(filter)
        if filter is False:
            msg.error("Wrong filter! Return to default")
            if type == "UDP":
                filter = PortStatus.OPEN_OR_FILTERED
            else:
                filter = PortStatus.OPEN
    start = time.perf_counter()
    with Progress() as progress:
        task = progress.add_task("Scanning ports.. ", total=len(ports))
        callback = partial(progress_cb, progress=progress, task=task)
        with Scanner(host=socket.gethostbyname(host), pool_size=256, rtt_timeout=retry_timeout,
                     time_between_packets_ms=20, on_port_scanned=callback) as scn:
            msg.info(f"{type} scan stared!")
            result = await scn.scan(scan_type=scan_type[type], ports=ports)
    result = [x for x in result.values() if x.status == filter]
    stop = time.perf_counter()
    msg.success("Done!")
    msg.info(f"Time: {stop - start:.2f}")
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


@app.command(name="scripts", help="List of available default scripts")
def script_lst():
    return_script_list()


@app.command(name="udp", help="UDP Scan")
@coro
async def udp_scan(
        host: str = typer.Option(default="", help=HelpMsg.host),
        port: str = typer.Option(default="d", help=HelpMsg.port),
        retry_timeout: int = typer.Option(default=1, help=HelpMsg.retry_timeout),
        output: bool = typer.Option(default=False, help=HelpMsg.output),
        script: str = typer.Option(default=None, help=HelpMsg.script),
        filter: str = typer.Option(default="open_or_filtered", help=HelpMsg.filter)
):
    await execute_scan("UDP", host, port, retry_timeout, output, script, filter)


@app.command(name="syn", help="TCP SYN scan")
@coro
async def tcp_syn_scan(
        host: str = typer.Option(help=HelpMsg.host),
        port: str = typer.Option(default="d", help=HelpMsg.port),
        retry_timeout: int = typer.Option(default=1, help=HelpMsg.retry_timeout),
        output: bool = typer.Option(default=False, help=HelpMsg.output),
        script: str = typer.Option(default=None, help=HelpMsg.script),
        filter: str = typer.Option(default="open", help=HelpMsg.filter),
        packet_timeout: int = typer.Option(default=20, help=HelpMsg.packet_timeout)
):
    await execute_scan("TCP SYN", host, port, retry_timeout, output, script, filter,packet_timeout)


@app.command(name="fin", help="TCP FIN scan")
@coro
async def tcp_fin_scan(
         host: str = typer.Option(help=HelpMsg.host),
        port: str = typer.Option(default="d", help=HelpMsg.port),
        retry_timeout: int = typer.Option(default=1, help=HelpMsg.retry_timeout),
        output: bool = typer.Option(default=False, help=HelpMsg.output),
        script: str = typer.Option(default=None, help=HelpMsg.script),
        filter: str = typer.Option(default="open", help=HelpMsg.filter),
        flag: str = typer.Option(help=HelpMsg.flag),
        packet_timeout: int = typer.Option(default=20, help=HelpMsg.packet_timeout)
):
    await execute_scan("TCP FIN", host, port, retry_timeout, output, script, filter, flag, packet_timeout)


@app.command(name="null", help="TCP NULL scan")
@coro
async def tcp_null_scan(
         host: str = typer.Option(help=HelpMsg.host),
        port: str = typer.Option(default="d", help=HelpMsg.port),
        retry_timeout: int = typer.Option(default=1, help=HelpMsg.retry_timeout),
        output: bool = typer.Option(default=False, help=HelpMsg.output),
        script: str = typer.Option(default=None, help=HelpMsg.script),
        filter: str = typer.Option(default="open", help=HelpMsg.filter),
        packet_timeout: int = typer.Option(default=20, help=HelpMsg.packet_timeout)
):
    await execute_scan("TCP NULL", host, port, retry_timeout, output, script, filter, packet_timeout)


@app.command(name="xmas", help="TCP XMAS scan")
@coro
async def tcp_xmas_scan(
         host: str = typer.Option(help=HelpMsg.host),
        port: str = typer.Option(default="d", help=HelpMsg.port),
        retry_timeout: int = typer.Option(default=1, help=HelpMsg.retry_timeout),
        output: bool = typer.Option(default=False, help=HelpMsg.output),
        script: str = typer.Option(default=None, help=HelpMsg.script),
        filter: str = typer.Option(default="open", help=HelpMsg.filter),
        packet_timeout: int = typer.Option(default=20, help=HelpMsg.packet_timeout)
):
    await execute_scan("TCP XMAS", host, port, retry_timeout, output, script, filter, packet_timeout)


@app.callback()
def banner(basic: bool = False):
    if basic is False:
        print_banner()
    state["basic"] = basic

def main():
    if os.geteuid() != 0:
        msg.error("need sudo to run this masterpiece")
        sys.exit(0)
    app()

if __name__ == "__main__":
    main()
