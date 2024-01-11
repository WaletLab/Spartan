import socket
from struct import pack
from scapy.all import IP, TCP
# from construct import Struct, Int8ul, Int16ul, Int32ul, Bytes


class Packet:
    def __init__(self, source_ip, destination_ip, destination_port):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        print(self.destination_port)
        # self.raw = self.build_packet()

    def build_packet(self):
        packet = IP(dst=self.destination_ip)/TCP(dport=self.destination_port, flags="S")
        return bytes(packet)
        # # Budowanie nagłówka IP
        # ip_header = pack('!BBHHHBBH4s4s', 69, 5, 20, 0, 0, 64, 6, 0, socket.inet_aton(self.source_ip), socket.inet_aton(self.destination_ip))
        #
        # # Budowanie nagłówka TCP
        # tcp_header = pack('!HHLLBBHHH', 12345, self.destination_port, 0, 0, 5 << 4, 2, 8192, 0, 0)
        #
        # # Pseudo-nagłówek
        # pseudo_header = pack('!4s4sBBH', socket.inet_aton(self.source_ip), socket.inet_aton(self.destination_ip), 0, 6, len(tcp_header))
        #
        # # Suma kontrolna
        # checksum = self.calculate_checksum(pseudo_header + tcp_header)
        #
        # # Ustawienie sumy kontrolnej w nagłówku TCP
        # tcp_header = tcp_header[:16] + pack('H', checksum) + tcp_header[18:]
        #
        # # Łączenie nagłówków IP i TCP
        # packet = (ip_header + tcp_header)
        # print("Długość pakietu {}".format(len(packet)))
        # return packet
    # def build_packet(self):
    #     ip_header = Struct(
    #         "version_ihl" / Int8ul,
    #         "dscp_ecn" / Int8ul,
    #         "total_length" / Int16ul,
    #         "identification_flags_fragment_offset" / Int32ul,
    #         "ttl_protocol_checksum" / Int32ul,
    #         "source_ip" / Bytes(4),
    #         "destination_ip" / Bytes(4),
    #     )

    #     tcp_header = Struct(
    #         "source_port" / Int16ul,
    #         "destination_port" / Int16ul,
    #         "sequence_number" / Int32ul,
    #         "acknowledgment_number" / Int32ul,
    #         "data_offset_flags_window" / Int32ul,
    #         "checksum_urgent_pointer" / Int32ul,
    #     )

    #     ip_header_bytes = ip_header.build({
    #         "version_ihl": 69,
    #         "dscp_ecn": 0,
    #         "total_length": 5,  # Długość nagłówka IP + długość nagłówka TCP
    #         "identification_flags_fragment_offset": 0,
    #         "ttl_protocol_checksum": (64 << 16) + 6,
    #         "source_ip": socket.inet_aton(self.source_ip),
    #         "destination_ip": socket.inet_aton(self.destination_ip),
    #     })

    #     tcp_header_bytes = tcp_header.build({
    #         "source_port": 12345,
    #         "destination_port": self.destination_port,
    #         "sequence_number": 0,
    #         "acknowledgment_number": 0,
    #         "data_offset_flags_window": (5 << 12) + (2 << 9) + 8192,
    #         "checksum_urgent_pointer": 0,
    #     })

    #     # Pole 'data offset' w nagłówku TCP reprezentuje długość w jednostkach 32-bitowych słów
    #     data_offset = (len(tcp_header_bytes) // 4) << 4
    #     tcp_header_bytes = tcp_header_bytes[:12] + Int8ul.build(data_offset) + tcp_header_bytes[13:]

    #     pseudo_header = ip_header_bytes[:12] + b'\x00\x06' + Int16ul.build(len(tcp_header_bytes))

    #     # Ustawienie checksum na 0 przed obliczeniem
    #     tcp_header_bytes = tcp_header_bytes[:16] + Int16ul.build(0) + tcp_header_bytes[18:]

    #     # Obliczenie sumy kontrolnej
    #     checksum = self.calculate_checksum(pseudo_header + tcp_header_bytes)
    #     tcp_header_bytes = tcp_header_bytes[:16] + Int16ul.build(checksum) + tcp_header_bytes[18:]

    #     packet = ip_header_bytes + tcp_header_bytes
    #     print("Długość pakietu {}".format(len(packet)))
    #     return packet



    @staticmethod
    def calculate_checksum(data):
        if len(data) % 2 != 0:
            data += b'\x00'
        s = sum([int.from_bytes(data[i:i+2], byteorder='big') for i in range(0, len(data), 2)])
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        return ~s & 0xffff
