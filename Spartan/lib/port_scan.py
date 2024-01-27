import time
import signal
import socket
import sys
import threading
from queue import Queue
from struct import *
from Spartan.lib.packet import IPHeader, create_ip_packet
from Spartan.lib.objects import Ports, Counter, Printer


class Scanner:
    def __init__(self, target, mode, range_start=None, range_end=None, port=None):
        self.target = target
        self.open_ports = Ports()
        self.jobs = Ports()
        self.mode = mode
        if self.mode == "all ports":
            self.jobs.all_ports()
        elif self.mode == "range ports":
            self.jobs.range_ports(range_start, range_end)
        elif self.mode == "single port":
            self.jobs.single_port(port)
        elif self.mode == "top port":
            self.jobs.top_port()
        self.len_jobs = len(self.jobs)
        self.q = Queue()
        self.N_THREADS = 300
        self.event = threading.Event()
        self.src_ip = self.get_source_ip()
        self.print_lock = Printer()
        self.pkt_counter = Counter()
        self.open_ports_lock = threading.Lock()

    def sig_handler(self, signum, frame):
        self.event.set()
        print(f'\n\nCaught Ctrl-C, Terminating...')
        time.sleep(0.5)
        sys.exit(0)

    def get_source_ip(self):
        res = [(s.connect((self.target, 53)), s.getsockname()[0], s.close()) \
               for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
        return res

    def listener(self):
        import struct
        listen = socket.socket(socket.AF_INET, socket.SOCK_RAW)
        while not self.event.is_set():
            try:
                packet = listen.recv(65565)
                ip_header = packet[:20]
                ip_fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
                ip_header_length = (ip_header[0] & 0xF) * 4
                tcp_header = packet[20:40]
                tcp_fields = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcp_fields[0]
                data_offset_reserved_flags = tcp_fields[4]
                data_offset = (data_offset_reserved_flags >> 12) * 4  # Obliczenie offsetu danych w bajtach
                reserved = (data_offset_reserved_flags >> 9) & 0x7
                flags = data_offset_reserved_flags & 0x1FF
                # print(flags if flags == 12 else flags)
                print(flags)
                if flags == 18:  # SYN-ACK
                    with self.open_ports_lock:
                        self.open_ports.add(src_port)
            except Exception as e:
                print(f"error {e}")

    def scan(self, port):
        import ctypes
        print(port)
        packet = IPHeader()
        ip_header, payload = create_ip_packet(dest_ip=self.target, source_ip=self.src_ip, payload=b"Hello, World")
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        dest_addr = (self.target, port)
        s.sendto(ctypes.string_at(ctypes.pointer(ip_header), ctypes.sizeof(ip_header)) + payload, dest_addr)
        print("wyslalem")
        s.close()
        self.pkt_counter.increment()
        if self.mode == "all ports" or self.mode == "range ports":
            time.sleep(0.01)
            progress = (self.pkt_counter / 65535) * 100
            progress = format(progress, '.0f')
            if port == 65535:
                time.sleep(0.1)
        else:
            time.sleep(0.5)
            progress = 100

        with self.print_lock:
            print(f'Progress: % {progress}', end='')
            print(f'\r', end='')

    def scan_thread(self):
        while not self.event.is_set():
            port = self.q.get()
            self.scan(port)
            self.q.task_done()

    def start_scan(self):
        signal.signal(signal.SIGINT, self.sig_handler)

        listener_thread = threading.Thread(target=self.listener, daemon=True)
        listener_thread.start()

        for worker in self.jobs.ports:
            self.q.put(worker)

        for t in range(self.N_THREADS):
            t = threading.Thread(target=self.scan_thread, daemon=True)
            t.start()

        self.q.join()

        self.open_ports.get_services()

        result = self.open_ports.show_results()
        return result
