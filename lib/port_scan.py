import socket
import time
from contextlib import contextmanager
import asyncio
from .helpers import Port


class Scanner:
    def __init__(self, host, ports, timeout=0.5, mode=False):
        self.ports = ports
        self.target = host
        self.timeout = timeout
        self.total_time = float()
        self._observers = list()
        self.scan_list = []
        self._loop = asyncio.new_event_loop()
        self.temp = []
        self.response = None
        self.mode = mode

    @property
    def _scan_tasks(self):
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
        info = False
        try:
            red, writer = await asyncio.wait_for(
                asyncio.open_connection(addr, port), timeout=self.timeout)
            if self.mode is not False:
                info = await Port().check_port(addr=addr, port=port, red=red, writer=writer)
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
