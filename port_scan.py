import socket
import time
from contextlib import contextmanager
import asyncio

import helpers


def get_service(port, typ):
    try:
        result = socket.getservbyport(port, typ)
        if result:
            print(port, result)
            return result
    except OSError:
        pass


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
    def __init__(self, host, ports, timeout=0.5):
        self.ports = ports
        self.target = host
        self.timeout = timeout
        self.total_time = float()
        self._observers = list()
        self.scan_list = []
        self._loop = asyncio.new_event_loop()
        self.temp = []
        self.response = None

    @property
    def _scan_tasks(self):
        """setup a corutine for pair target-port"""
        tmp = []
        for port in self.ports:
            for p in port:
                tmp.append(self._scan_target_port(self.target, p))
            return tmp

    @contextmanager
    def _timer(self):
        start_time = time.perf_counter()
        yield
        self.total_time = time.perf_counter() - start_time

    def register(self, observer):
        self._observers.append(observer)

    async def _notify(self):
        [asyncio.create_task(observer.update()) for observer in self._observers]

    async def _scan_target_port(self, addr, port):
        temp_dict = {'type': "TCP", 'port': port, 'status': None, 'service': None, 'info': None}
        try:
            red, writer = await asyncio.wait_for(
                asyncio.open_connection(addr, port), timeout=self.timeout)
            info = await helpers.Port().check_port(addr=addr, port=port, red=red, writer=writer)
            if info:
                temp_dict['info'] = info
            temp_dict['status'] = "OPEN"
            self.scan_list.append(temp_dict)
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            pass
        try:
            temp_dict['service'] = socket.getservbyport(port)
        except OSError:
            temp_dict['service'] = 'unknown'

    def execute(self):
        with self._timer():
            self._loop.run_until_complete(asyncio.wait(self._scan_tasks))
        self._loop.run_until_complete(self._notify())
        return self.scan_list
