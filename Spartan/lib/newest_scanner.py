import time
import random
import asyncio
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from typing import Tuple, Any, Iterable, Callable

from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.all import Raw, RandShort, Packet, AsyncSniffer
from scapy.sendrecv import sr, sr1, send
from scapy.supersocket import L3RawSocket

from .helpers.helpers import Port


class ScanType:
    TCP_SYN = "TCP_SYN"
    TCP_FIN = "TCP_FIN"
    TCP_NULL = "TCP_NULL"
    TCP_XMAS = "TCP_XMAS"
    # TODO
    # TCP_CON = "TCP_CON"
    UDP = "UDP"


class PortStatus:
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    FILTERED = "FILTERED"
    OPEN_OR_FILTERED = "OPEN OR FILTERED"
    AWAITING = "AWAITING"


class StatusDetail:
    NONE = ""
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
    def __init__(self, port: int, status: str, detail: str,
                 probe_pkt: Packet | None = None, probed_at: datetime | None = None,
                 retries: int = 0):
        self.port = port
        self.status = status
        self.detail = detail
        self.probe_pkt = probe_pkt
        self.probed_at = probed_at
        self.retries = retries


class Scanner:
    def __init__(self,
                 host: str,
                 max_retries: int = 3,
                 rtt_timeout: int = 1,
                 time_between_packets_ms: int | None = None,
                 time_between_retries_ms: int | None = None,
                 pool_size: int = 1024):
        self._host = host
        self._retries = max_retries
        self._rtt_timeout = rtt_timeout
        # TODO
        self._time_between_packets_ms = time_between_packets_ms
        self._time_between_retries_ms = time_between_retries_ms
        self._pool_size = pool_size
        self._sock: L3RawSocket | None = None
        self._sniffer: AsyncSniffer | None = None
        self._pkt_handler_proper: Callable[[Packet], PortResult] | None = None
        self._results: dict[int, PortResult] = {}

    def __enter__(self):
        self._sock = L3RawSocket()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._sock.close()

    def _pkt_handler_dispatch(self, pkt: Packet):
        if not self._pkt_handler_proper:
            raise RuntimeError("Something's wrong with packet handling. Investigate.")
        result = self._pkt_handler_proper(pkt)
        if result:
            self._results[result.port] = result

    async def scan(self, method: str, ports: Iterable) -> dict[int, PortResult]:
        if not self._sock:
            raise RuntimeError("Scanner has to be instantiated with a with statement")

        def init_sniffer(handler: Callable[[Packet], PortResult], filter: str):
            self._pkt_handler_proper = handler
            # *should* drop packets like flies when they flow in at a fast rate
            # test whether that's the case
            self._sniffer = AsyncSniffer(prn=self._pkt_handler_dispatch, filter=filter)
            self._sniffer.start()

        match method:
            case ScanType.TCP_SYN:
                init_sniffer(self._tcp_syn_pkt_handler, "(tcp or icmp) and src host %s" % self._host)
                self.tcp_syn_scan(ports)
            case ScanType.TCP_FIN:
                init_sniffer(self._tcp_pkt_handler, "(tcp or icmp) and src host %s" % self._host)
                self.tcp_scan(ports, "F")
            case ScanType.TCP_NULL:
                init_sniffer(self._tcp_pkt_handler, "(tcp or icmp) and src host %s" % self._host)
                self.tcp_scan(ports, "")
            case ScanType.TCP_XMAS:
                init_sniffer(self._tcp_pkt_handler, "(tcp or icmp) and src host %s" % self._host)
                self.tcp_scan(ports, "FPU")
            # TODO
            # case ScanType.TCP_CON:
            case ScanType.UDP:
                init_sniffer(self._udp_pkt_handler, "(udp or icmp) and src host %s" % self._host)
                self.udp_scan(ports)
            case _:
                raise RuntimeError("Unknown method %s" % method)

        anything_left = True
        while anything_left:
            anything_left = False
            for result in self._results.values():
                if result.status != PortStatus.AWAITING:
                    continue
                if result.retries > self._retries:
                    continue
                anything_left = True
                elapsed = datetime.now() - result.probed_at
                if elapsed < timedelta(seconds=self._rtt_timeout):
                    continue
                self._send(result.probe_pkt)
                result.retries += 1
                result.probed_at = datetime.now()
                if self._time_between_retries_ms:
                  await asyncio.sleep(self._time_between_retries_ms)
            await asyncio.sleep(0.5)
        self._pkt_handler_proper = None
        match method:
            case ScanType.TCP_SYN:
                real_results = {k: PortResult(v.port, PortStatus.FILTERED, v.detail) if v.status == PortStatus.AWAITING else v
                                for k, v in self._results.items()}
            case ScanType.TCP_FIN | ScanType.TCP_XMAS | ScanType.TCP_NULL | ScanType.UDP:
                real_results = {k: PortResult(v.port, PortStatus.OPEN_OR_FILTERED, v.detail) if v.status == PortStatus.AWAITING else v
                                for k, v in self._results.items()}
            case _:
                real_results = {k: v for k, v in self._results.items() if v.status != PortStatus.AWAITING}

        return real_results

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
        pkt = IP(dst=self._host) / TCP(sport=sport, dport=port, flags=flags) / Raw(b"")
        self._send(pkt)
        self._results[port] = PortResult(port, PortStatus.AWAITING, StatusDetail.NONE,
                                         pkt, datetime.now())

    def tcp_various_flags_scan_port(self, port: int, flags: str):
        sport = RandShort()
        pkt = IP(dst=self._host) / TCP(sport=sport, dport=port, flags=flags) / Raw(b"")
        self._send(pkt)
        self._results[port] = PortResult(port, PortStatus.AWAITING, StatusDetail.NONE,
                                         pkt, datetime.now())

    def udp_scan_port(self, port: int):
        pkt = IP(dst=self._host) / UDP(sport=RandShort(), dport=port) / Raw(b"")
        self._send(pkt)
        self._results[port] = PortResult(port, PortStatus.AWAITING, StatusDetail.NONE,
                                         pkt, datetime.now())

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
            if pkt[ICMP].type == 3 and pkt[ICMP].code in [1, 2, 3, 9, 10, 13]:
                return PortResult(port, PortStatus.FILTERED, detail=StatusDetail.ICMP)

    def _tcp_pkt_handler(self, pkt: Packet):
        port = pkt[TCP].sport
        if pkt.haslayer(TCP) and pkt[TCP].flags.R:  # RST
            return PortResult(port, PortStatus.CLOSED, detail=StatusDetail.TCP)
        elif pkt.haslayer(ICMP):
            if pkt[ICMP].type == 3 and pkt[ICMP].code in [1, 2, 3, 9, 10, 13]:
                return PortResult(port, PortStatus.FILTERED, detail=StatusDetail.ICMP)

    def _udp_pkt_handler(self, pkt: Packet):
        port = pkt[IP].sport
        if pkt.haslayer(UDP):
            return PortResult(port, PortStatus.OPEN, detail=StatusDetail.UDP)
        elif pkt.haslayer(ICMP):
            if pkt[ICMP].type == 3:
                if pkt[ICMP].code == 3:
                    return PortResult(port, PortStatus.CLOSED, detail=StatusDetail.ICMP)
                elif pkt[ICMP].code in [1, 2, 9, 10, 13]:
                    return PortResult(port, PortStatus.FILTERED, detail=StatusDetail.ICMP)

    def tcp_syn_scan(self, ports: Iterable):
        self._run_async_midfast(self.tcp_syn_scan_port, ports, "S")

    def tcp_scan(self, ports: Iterable, flags):
        self._run_async_midfast(self.tcp_various_flags_scan_port, ports, flags)

    def udp_scan(self, ports: Iterable):
        self._run_async_midfast(self.udp_scan_port, ports, None)


async def main():
    with Scanner("45.33.32.156", pool_size=256, rtt_timeout=3) as scn:
        result = await scn.scan(ScanType.UDP, top_ports_shuffled())
    result = [x for x in result.values() if x.status != PortStatus.CLOSED]
    for x in result:
            print(x.port, x.status, x.detail)


if __name__ == "__main__":
    asyncio.run(main())
