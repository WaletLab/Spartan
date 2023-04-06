import socket
import time
from concurrent.futures import ThreadPoolExecutor
import os
# import re


def get_service(port, typ):
    try:
        result = socket.getservbyport(port, typ)
        if result:
            print(port, result)
            return result
    except OSError:
        pass


def split_port_lists(lst, chunk_size):
    result = [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
    return result


def check_html_response(data):
    from helpers import find_pattern
    server_info = find_pattern(b"Server: (.+?)\r\n", data)
    date_info = find_pattern(rb'Date: (.+?)\r\n', data)
    content_type_info = find_pattern(rb'Content-Type: (.+?)\r\n', data)
    transfer_encoding_info = find_pattern(rb'Transfer-Encoding: (.+?)\r\n', data)
    accept_ranges_info = find_pattern(rb'Accept-Ranges: (.+?)\r\n', data)
    vary_info = find_pattern(rb'Vary: (.+?)\r\n', data)
    return {"server": server_info.group(1).decode(),
            "date": date_info.group(1).decode(),
            "content": content_type_info.group(1).decode(),
            "transfer": transfer_encoding_info.group(1).decode(),
            "accpet-range": accept_ranges_info.group(1).decode(),
            "vary": vary_info.group(1).decode()
            }


class Scanner:

    def __init__(self):
        self.scan_list = []
        self.stop = False

    def scan(self, hostname, port=None, port_range=None, udp=True):
        with ThreadPoolExecutor(max_workers=max(32, os.cpu_count() + 4)) as executor:
            if hostname:
                if port is not None:
                    self._scan(hostname, port, udp)
                elif port_range:
                    lst = [x for x in range(int(port_range['start']), int(port_range['stop']))]
                    chunk_size = 10
                    ports = split_port_lists(lst, chunk_size)
                    for single in ports:
                        executor.map(lambda p: self._scan(hostname, p, udp), single)
                else:
                    lst = [x for x in range(1, 65535)]
                    chunk_size = 100
                    ports = split_port_lists(lst, chunk_size)
                    for port in ports:
                        executor.map(lambda p: self._scan(hostname, p, udp), port)
                self.stop = True
                executor.shutdown(wait=True)
                print(self.scan_list)
                for scan in self.scan_list:
                    scan['service'] = get_service(scan['port'], scan['type'])
                return self.scan_list
            else:
                return ValueError("no hostname")

    def _scan(self, hostname, port, udp):
        if self.stop:
            return
        temp_dict_tcp = {"type": None, "port": None, "status": None,
                         "service": None, "info": None}
        temp_dict_udp = {"type": None, "port": None, "status": None,
                         "service": None, "info": None}
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.8)
            target = socket.gethostbyname(hostname)
            result = s.connect_ex((target, port))
            if result == 0:
                temp_dict_tcp['type'] = "tcp"
                temp_dict_tcp['port'] = port
                temp_dict_tcp['status'] = "OPEN"
                if port == 80:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
                    html_data = s.recv(1024)
                    parse_html_data = check_html_response(html_data)
                    strings = ""
                    if parse_html_data:
                        for key in parse_html_data.keys():
                            strings += f"{key}: {parse_html_data[key]} \n"
                        temp_dict_tcp['info'] = strings
                try:
                    if port != 80:
                        data = s.recv(1024)
                        if data:
                            temp_dict_tcp['info'] = data.decode('utf-8')
                except TimeoutError:
                    temp_dict_tcp['info'] = None
                self.scan_list.append(temp_dict_tcp)
        if udp:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.settimeout(1)
                target = socket.gethostbyname(hostname)
                result = u.connect_ex((target, port))
                if result == 0:
                    temp_dict_udp['type'] = "udp"
                    temp_dict_udp['port'] = port
                    temp_dict_udp['status'] = "OPEN"
                    try:
                        data = u.recv(1024)
                        if data:
                            temp_dict_udp['info'] = data.decode('utf-8')
                    except TimeoutError:
                        temp_dict_udp['info'] = None
                    self.scan_list.append(temp_dict_udp)
