import time
import random
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from typing import Tuple, Any, Iterable, Callable

from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.all import Raw, RandShort, Packet, AsyncSniffer
from scapy.sendrecv import sr, sr1, send
from scapy.supersocket import L3RawSocket

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
        self._sock: L3RawSocket | None = None
        self._sniffer: AsyncSniffer | None = None
        self._pkt_handler_proper: Callable[[Packet], PortResult] | None = None
        self._results: list[PortResult] = []

    def __enter__(self):
        self._sock = L3RawSocket()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._sock.close()

    def _pkt_handler_dispatch(self, pkt: Packet):
        if not self._pkt_handler_proper:
            raise RuntimeError("Something's wrong with packet handling. Investigate.")
        self._results.append(self._pkt_handler_proper(pkt))

    def scan(self, method: str, ports: Iterable) -> list[PortResult]:
        if not self._sock:
            raise RuntimeError("Scanner has to be instantiated with a with statement")

        def init_sniffer(handler: Callable[[Packet], PortResult], filter: str):
            self._pkt_handler_proper = handler
            # *should* drop packets like flies when they flow in at a fast rate
            # test whether that's the case
            self._sniffer = AsyncSniffer(opened_socket=self._sock, prn=self._pkt_handler_dispatch, filter=filter)
            self._sniffer.start()

        match method:
            case ScanType.TCP_SYN:
                init_sniffer(self._tcp_syn_pkt_handler, "tcp and host %s" % self._host)
                self.tcp_syn_scan(ports)
            case ScanType.TCP_FIN:
                init_sniffer(self._tcp_pkt_handler, "tcp and host %s" % self._host)
                self.tcp_scan(ports, "F")
            case ScanType.TCP_NULL:
                init_sniffer(self._tcp_pkt_handler, "tcp and host %s" % self._host)
                self.tcp_scan(ports, "")
            case ScanType.TCP_XMAS:
                init_sniffer(self._tcp_pkt_handler, "tcp and host %s" % self._host)
                self.tcp_scan(ports, "FPU")
            case ScanType.UDP:
                init_sniffer(self._udp_pkt_handler, "udp and host %s" % self._host)
                self.udp_scan(ports)
            case _:
                raise RuntimeError("Unknown method %s" % method)
        # Imagine a wait for conditions outlines below here
        time.sleep(5)
        # Implement resending packets (not here)
        # Do something about unhandled ports
        self._pkt_handler_proper = None
        return self._results

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

    def _send(self, packet: Packet):
        self._sock.send(packet)

    def tcp_syn_scan_port(self, port: int, flags: str):
        sport = RandShort()
        self._send(IP(dst=self._host) / TCP(sport=sport, dport=port, flags=flags) / Raw(b""))

    def tcp_various_flags_scan_port(self, port: int, flags: str):
        sport = RandShort()
        self._send(IP(dst=self._host) / TCP(sport=sport, dport=port, flags=flags) / Raw(b""))

    def udp_scan_port(self, port: int):
        self._send(IP(dst=self._host) / UDP(sport=RandShort(), dport=port) / Raw(b""))

    def _tcp_syn_pkt_handler(self, pkt: Packet):
        port = pkt[TCP].sport
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

    def _tcp_pkt_handler(self, pkt: Packet):
        port = pkt[TCP].sport
        if pkt.haslayer(TCP) and pkt[TCP].flags.R:  # RST
            return PortResult(port, PortStatus.CLOSED, detail=StatusDetail.TCP)
        elif pkt.haslayer(ICMP):
            return PortResult(port, PortStatus.FILTERED, detail=StatusDetail.ICMP)

    def _udp_pkt_handler(self, pkt: Packet):
        port = pkt[IP].sport
        if pkt.haslayer(UDP):
            return PortResult(port, PortStatus.OPEN, detail=StatusDetail.UDP)
        elif pkt.haslayer(ICMP):
            return PortResult(port, PortStatus.OPEN_OR_FILTERED, detail=StatusDetail.ICMP)

    def tcp_syn_scan(self, ports: Iterable):
        self._run_async_midfast(self.tcp_syn_scan_port, ports, "S")

    def tcp_scan(self, ports: Iterable, flags):
        self._run_async_midfast(self.tcp_various_flags_scan_port, ports, flags)

    def udp_scan(self, ports: Iterable):
        self._run_async_midfast(self.udp_scan_port, ports, None)


def main():
    with Scanner("45.33.32.156", pool_size=256) as scn:
        result = scn.scan(ScanType.UDP, top_ports_shuffled())
    result = [x for x in result if x.status != PortStatus.CLOSED]
    for x in result:
        print(x.port, x.status, x.detail)
    print(len(result))


if __name__ == "__main__":
    main()
