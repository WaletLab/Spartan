import time
import signal
import socket
import sys
import os
import fcntl
import threading
from queue import Queue
from struct import *
from Spartan.lib.packet import Packet
from Spartan.lib.objects import Ports, Counter, Printer
# from scapy.all import IP, TCP, send
### poprawka dla macos
# def enable_promiscuous_mode(interface):
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     try:
#         fcntl.ioctl(s.fileno(), 0x8913, pack('256s', bytes(interface[:15], 'utf-8')))
#     except Exception as e:
#         print(f"Błąd podczas włączania trybu promiskuitywnego: {e}")    

# enable_promiscuous_mode("en0")


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
        listen = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # listen.settimeout(5)
        print("jestem tutaj")
        while not self.event.is_set():
            try:
                print("jestem w while")
                packet = listen.recv(65565)
                # print(packet)
                ip_header = unpack('!BBHHHBBH4s4s', packet[0:20])
                ip_head_len = (ip_header[0] & 0xf) * 4

                tcp_header_raw = packet[ip_head_len:ip_head_len + 14]
                tcp_header = unpack('!HHLLBBHHH', tcp_header_raw)

                src_port = tcp_header[0]
                flag = tcp_header[5]
                print(flag)
                if flag == 18:  # SYN-ACK
                    with self.open_ports_lock:
                        self.open_ports.add(src_port)
            except Exception as e:
                print(e)
    def scan(self, port):
        packet = Packet(self.src_ip, self.target, port)
        packet = packet.build_packet()
        print(len(packet))
        # print(packet.raw)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # s.setsockopt(socket.IPPROTO_IP, 1)
        s.sendto(packet, (self.target, 0))
        s.close()
        self.pkt_counter.increment()
        if self.mode =="all ports" or self.mode == "range ports":
            time.sleep(0.01)
            progress = (self.pkt_counter / 65535) * 100
            progress = format(progress, '.0f')
            if port == 65535:  # To fix scan ending on less then 100 %
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
        print(listener_thread)

        for worker in self.jobs.ports:
            self.q.put(worker)

        for t in range(self.N_THREADS):
            t = threading.Thread(target=self.scan_thread, daemon=True)
            t.start()

        self.q.join()

        # print("Scan completed")
        # with self.open_ports_lock:

        self.open_ports.get_services()

        result = self.open_ports.show_results()
        return result