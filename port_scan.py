import socket
from concurrent.futures import ThreadPoolExecutor
import os

class Scanner:

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=max(32, os.cpu_count() + 4))
        print(max(32, os.cpu_count() + 4))
        self.scan_list = []
    def split_port_lists(self, lst, chunk_size):
        result = [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
        return result
    def scan(self, hostname, port=None, port_range=None):
        if hostname:
            if port:
                self._scan(hostname, port)
            elif port_range:
                lst = [x for x in range(port_range['start'], port_range['stop'])]
                chunk_size = 10
                ports = self.split_port_lists(lst, chunk_size)
                for port in ports:
                    self.executor.map(lambda p: self._scan(hostname, p), port)
            else:
                lst = [x for x in range(1, 65535)]
                chunk_size = 10000
                ports = self.split_port_lists(lst, chunk_size)
                for port in ports:
                    print("sprawdzam paczke:")
                    print(port)
                    self.executor.map(lambda p: self._scan(hostname, p), port)
            return self.scan_list
        else:
            return ValueError("no hostname")

    def _scan(self, hostname, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # try:
            target = socket.gethostbyname(hostname)
            result = s.connect_ex((target, port))
            if result == 0:
                self.scan_list.append({"port": port, "status": "open"})
