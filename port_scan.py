import socket
import time
from contextlib import contextmanager
import asyncio


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
    def __init__(self, host, ports, timeout=1):
        self.ports = ports
        self.target = host
        self.timeout = timeout
        self.total_time = float()
        self._observers = list()
        self.scan_list = []
        self._loop = asyncio.new_event_loop()

    @property
    def _scan_tasks(self):
        """setup a corutine for pair target-port"""
        return [self._scan_target_port(target, port) for port in self.ports for target in [self.target]]

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
            await asyncio.wait_for(
                asyncio.open_connection(addr, port), timeout=self.timeout)

            temp_dict['status'] = "OPEN"
            self.scan_list.append(temp_dict)
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            # # reason = {
            # #     "ConnectionRe"
            # # }
            # temp_dict['port_state'] = "CLOSED"
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
