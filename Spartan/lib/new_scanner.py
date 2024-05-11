import threading
import random
import socket
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from typing import Tuple, Any, Iterable

from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.all import Raw, RandShort, Packet
from scapy.sendrecv import sr, sr1, send

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
    TCP = "TCP"
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
        self._retries = udp_retries
        self._timeout = timeout
        self._pool_size = pool_size

    def scan(self, method: str, ports: Iterable):
        match method:
            case ScanType.TCP_SYN:
                return self.tcp_syn_scan(ports)
            case ScanType.TCP_FIN:
                return self.tcp_various_flags_scan(ports, "F")
            case ScanType.TCP_NULL:
                return self.tcp_various_flags_scan(ports, "")
            case ScanType.TCP_XMAS:
                return self.tcp_various_flags_scan(ports, "FPU")
            case ScanType.UDP:
                return self.udp_scan(ports)
            case _:
                return None

    def _run_async_midfast(self, fn, args_list: Iterable[Tuple | Any], flags: str | None):
        with ThreadPoolExecutor(max_workers=self._pool_size) as pool:
            if flags:
                futures = [pool.submit(fn, args, flags) for args in args_list]
            else:
                futures = [pool.submit(fn, args) for args in args_list]
            completed, fucked = wait(futures, timeout=None, return_when=ALL_COMPLETED)
            if len(fucked):
                raise RuntimeError("something went wrong, call an exorcist")
            results = [x.result() for x in completed]
            return results

    def tcp_syn_scan(self, ports: Iterable):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        results = self._run_async_midfast(self.tcp_syn_scan_port, ports, "S")
        sock.close()
        return results

    def tcp_various_flags_scan(self, ports: Iterable, flags):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        results = self._run_async_midfast(self.tcp_various_flags_scan_port, ports, flags)
        sock.close()
        return results

    def udp_scan(self, ports: Iterable):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        results = self._run_async_midfast(self.udp_scan_port, ports, None)
        sock.close()
        return results

    def tcp_syn_scan_port(self, port: int, flags: str):
        sport = RandShort()
        pkt = IP(dst=self._host) / TCP(sport=sport, dport=port, flags=flags) / Raw(b"")
        recvd = sr1(pkt, retry=self._retries, timeout=self._timeout, multi=True, verbose=False)
        if not recvd:
            return PortResult(port, PortStatus.FILTERED, detail=StatusDetail.NO_RESP)
        else:
            pkt: Packet = recvd
            seq = pkt[TCP].ack
            dport = pkt[TCP].dport
            if pkt.haslayer(TCP) and pkt[TCP].flags == 0x12:  # SYN-ACK
                rst_pkt = IP(dst=self._host) / TCP(sport=dport, dport=port, flags="R", seq=seq) / Raw(b"")
                send(rst_pkt, verbose=False)
                return PortResult(port, PortStatus.OPEN, detail=StatusDetail.TCP)
            if pkt.haslayer(TCP) and pkt[TCP].flags.R:  # RST
                return PortResult(port, PortStatus.CLOSED, detail=StatusDetail.TCP)
            elif pkt.haslayer(ICMP):
                return PortResult(port, PortStatus.FILTERED, detail=StatusDetail.ICMP)

    def tcp_various_flags_scan_port(self, port: int, flags: str):
        sport = RandShort()
        pkt = IP(dst=self._host) / TCP(sport=sport, dport=port, flags=flags) / Raw(b"")
        recvd = sr1(pkt, retry=self._retries, timeout=self._timeout, multi=True, verbose=False)
        if not recvd:
            return PortResult(port, PortStatus.OPEN_OR_FILTERED, detail=StatusDetail.NO_RESP)
        else:
            pkt: Packet = recvd
            if pkt.haslayer(TCP) and pkt[TCP].flags.R:  # RST
                return PortResult(port, PortStatus.CLOSED, detail=StatusDetail.TCP)
            elif pkt.haslayer(ICMP):
                return PortResult(port, PortStatus.FILTERED, detail=StatusDetail.ICMP)

    def udp_scan_port(self, port: int):
        pkt = IP(dst=self._host) / UDP(sport=RandShort(), dport=port) / Raw(b"")
        recvd, unanswered = sr(pkt, retry=self._retries, timeout=self._timeout, multi=True, verbose=False)
        if not recvd:
            return PortResult(port, PortStatus.OPEN_OR_FILTERED, detail=StatusDetail.NO_RESP)
        else:
            for query_answer in recvd:
                pkt: Packet = query_answer.answer
                if pkt.haslayer(UDP):
                    return PortResult(port, PortStatus.OPEN, detail=StatusDetail.UDP)
                elif pkt.haslayer(ICMP):
                    return PortResult(port, PortStatus.OPEN_OR_FILTERED, detail=StatusDetail.ICMP)


def main():
    scn = Scanner("45.33.32.156", pool_size=64)
    result = scn.scan(ScanType.TCP_SYN, top_ports_shuffled())
    result = [x for x in result if x.status != PortStatus.CLOSED]
    for x in result:
        print(x.port, x.status, x.detail)
    print(len(result))


if __name__ == "__main__":
    main()
