import threading
import random
import socket
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from typing import Tuple, Any, Iterable

from scapy.layers.inet import IP, UDP, ICMP
from scapy.all import Raw, RandShort, Packet
from scapy.sendrecv import sr, sr1

from .helpers.helpers import Port

class ScanType:
    TCP_SYN = "TCP_SYN"
    TCP_CONNECTION = "TCP_CONNECTION"
    TCP_FIN = "TCP_FIN"
    TCP_NULL = "TCP_NULL"
    TCP_XMAS = "TCP_XMAS"
    UDP = "UDP"


class PortStatus:
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    FILTERED = "FILTERED"
    OPEN_OR_FILTERED = "OPEN OR FILTERED"


class StatusDetail:
    NO_RESP = "NO RESP"
    UDP = "UDP"
    ICMP = "ICMP"


class PortList:
    ALL = "ALL"
    TOP = "TOP"


def top_ports_shuffled() -> list[int]:
    ports = Port().top_ports
    random.shuffle(ports)
    return ports


def all_ports() -> Iterable:
    return range(1, 65536)


class PortResult:
    def __init__(self, port: int, status: str, detail: str = ""):
        self.port = port
        self.status = status
        self.detail = detail


class Scanner:
    def __init__(self, host: str, udp_retries: int = 3, timeout: int = 1, pool_size: int = 1024):
        self._host = host
        self._udp_retries = udp_retries
        self._timeout = timeout
        self._pool_size = pool_size

    def scan(self, method: str, ports: Iterable):
        match method:
            case ScanType.UDP:
                return self.udp_scan(ports)
            case _:
                return None

    def _run_async_midfast(self, fn, args_list: Iterable[Tuple | Any]):
        with ThreadPoolExecutor(max_workers=self._pool_size) as pool:
            futures = [pool.submit(fn, args) for args in args_list]
            completed, fucked = wait(futures, timeout=None, return_when=ALL_COMPLETED)
            if len(fucked):
                raise RuntimeError("something went wrong, call an exorcist")
            results = [x.result() for x in completed]
            return results

    def udp_scan(self, ports: Iterable):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        results = self._run_async_midfast(self.udp_scan_port, ports)
        sock.close()
        return results

    def udp_scan_port(self, port: int):
        pkt = IP(dst=self._host)/UDP(sport=RandShort(), dport=port)/Raw(b"a")
        sent, recvd = sr(pkt, retry=self._udp_retries, timeout=self._timeout, multi=True, verbose=False)
        if not recvd:
            return PortResult(port, PortStatus.OPEN_OR_FILTERED, detail=StatusDetail.NO_RESP)
        else:
            for pkt in recvd:
                pkt: Packet = pkt
                if pkt.haslayer(UDP):
                    return PortResult(port, PortStatus.OPEN, detail=StatusDetail.UDP)
                elif pkt.haslayer(ICMP):
                    return PortResult(port, PortStatus.OPEN_OR_FILTERED, detail=StatusDetail.ICMP)
                else:
                    print("asdf", pkt)


def main():
    scn = Scanner("45.33.32.156", pool_size=64)
    result = scn.scan(ScanType.UDP, top_ports_shuffled())
    result = [x for x in result if x.status != PortStatus.CLOSED]
    for x in result:
        print(x.port, x.status, x.detail)
    print(len(result))


if __name__ == "__main__":
    main()
