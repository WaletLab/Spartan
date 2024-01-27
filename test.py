import socket
import struct
import ctypes
from Spartan.lib.port_scan import Scanner

class IPHeader(ctypes.Structure):
    _fields_ = [
        ('version', ctypes.c_ubyte, 4),
        ('ihl', ctypes.c_ubyte, 4),
        ('tos', ctypes.c_ubyte),
        ('total_length', ctypes.c_ushort),
        ('identification', ctypes.c_ushort),
        ('flags_fragment_offset', ctypes.c_ushort),
        ('ttl', ctypes.c_ubyte),
        ('protocol', ctypes.c_ubyte),
        ('checksum', ctypes.c_ushort),
        ('source_address', ctypes.c_uint32),
        ('destination_address', ctypes.c_uint32)
    ]

def create_ip_packet(source_ip, dest_ip, payload, protocol=socket.IPPROTO_TCP):
    source_ip_numeric = struct.unpack('!I', socket.inet_aton(source_ip))[0]
    print(source_ip_numeric)
    dest_ip_numeric = struct.unpack('!I', socket.inet_aton(dest_ip))[0]
    print(dest_ip_numeric)
    ip_header = IPHeader(
        version=4,
        ihl=5,
        tos=0,
        total_length=ctypes.sizeof(IPHeader) + len(payload),
        identification=0,
        flags_fragment_offset=0,
        ttl=64,
        protocol=socket.IPPROTO_TCP,
        checksum=0,
        source_address=source_ip_numeric,
        destination_address=dest_ip_numeric
    )

    return ip_header, payload

def send_ip_packet(source_ip, dest_ip, payload, dest_port):
    ip_header, payload = create_ip_packet(source_ip, dest_ip, payload)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    dest_addr = (dest_ip, dest_port)
    s.sendto(ctypes.string_at(ctypes.pointer(ip_header), ctypes.sizeof(ip_header)) + payload, dest_addr)
    s.close()

def receive_tcp_response(source_ip, dest_ip, dest_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((source_ip, 0))
    s.connect((dest_ip, dest_port))
    response = s.recv(1024)  # Odbierz dane do 1024 bajtów
    s.close()
    return response

if __name__ == "__main__":
    source_ip = Scanner("192.168.1.1", "all_ports").get_source_ip()
    dest_ip = "192.168.0.104"
    dest_port = 80
    payload = b"Hello, world!"

    send_ip_packet(source_ip, dest_ip, payload, dest_port)
    response = receive_tcp_response(source_ip, dest_ip, dest_port)
    print("Otrzymana odpowiedź:", response)
