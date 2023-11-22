import re
import random
import threading


class Ports:
    def __init__(self):
        self.services = {}
        self.lock = threading.Lock()
        self.ports = []

    def __len__(self):
        return len(self.ports)

    def add(self, port):
        with self.lock:
            self.ports.append(port)

    def all_ports(self):
        self.ports = [i for i in range(1, 65536)]
        random.shuffle(self.ports)

    def single_port(self, port):
        self.ports = [port]
        random.shuffle(self.ports)

    def range_ports(self, range_start, range_end):
        self.ports = [i for i in range(int(range_start), int(range_end))]
        random.shuffle(self.ports)

    def top_port(self):
        from lib.helpers.helpers import Port
        self.ports = Port().top_ports
        # print(self.ports)
        random.shuffle(self.ports)


    def show(self):
        for port in self.ports:
            print(port)

    def get_services(self):
        with open('Spartan/lib/nmap-services', 'rt') as nmap_file:
            for port in sorted(self.ports):
                regex = re.compile(r'^.+\s' + re.escape(str(port)) + r'/tcp\s.+$')
                for line in nmap_file:
                    if regex.search(line):
                        line = line.strip('\n').split()
                        self.services[port] = {'port': line[1], 'state': 'open', 'service': line[0]}
                        break
                else:
                    self.services[port] = {'port': line[1], 'state': 'open', 'service': line[0]}

    def show_results(self):
        return self.services


class Counter:
    def __init__(self):
        self.lock = threading.Lock()
        self.packets = 0

    def __str__(self):
        return str(self.packets)

    def __truediv__(self, other):
        return self.packets / other

    def increment(self):
        with self.lock:
            self.packets += 1


class Printer:
    def __init__(self):
        self.lock = threading.Lock()

    def __enter__(self):
        return self.lock

    def __exit__(self, type, value, tb):
        pass
