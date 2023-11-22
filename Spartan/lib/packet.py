import random
import socket
from struct import *


class Packet:

    def __init__(self, src_ip, dest_ip, dest_port):
        # IP segment #
        self.ver = 0x4
        self.ihl = 0x5
        self.type_of_serv = 0x0
        self.total_len = 0x42
        self.ident = random.randint(1, 45535)
        self.flags = 0x2
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(self.src_ip)
        self.dest_addr = socket.inet_aton(self.dest_ip)
        self.v_ihl = (self.ver << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset

        _tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_serv, self.total_len,
                              self.ident, self.f_fo, self.ttl, self.protocol,
                              self.header_checksum, self.src_addr, self.dest_addr)

        self.ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_serv, self.total_len,
                              self.ident, self.f_fo, self.ttl, self.protocol,
                              self.calc_checksum(_tmp_ip_header), self.src_addr, self.dest_addr)


        # TCP header #
        self.src_port = random.randint(1000, 9400)
        self.dest_port = dest_port
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, \
            self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = ((self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (self.cwr << 7)
                                      + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3)
                                      + (self.rst << 2) + (self.syn << 1) + self.fin)

        _tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port, self.seq_no,
                               self.ack_no, self.data_offset_res_flags, self.window_size,
                               self.checksum, self.urg_pointer)
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol,
                             len(_tmp_tcp_header))
        psh = pseudo_header + _tmp_tcp_header
        self.tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port, self.seq_no, self.ack_no,
                                self.data_offset_res_flags, self.window_size, self.calc_checksum(psh),
                                self.urg_pointer)

        self.raw = self.ip_header + self.tcp_header

    def calc_checksum(self, data):
        check = 0
        len_data = len(data)
        if len_data % 2:
            len_data += 1
            data += pack('!B',0)
        for i in range(0, len_data, 2):
            w = (data[i] << 8 ) + (data[i+1])
            check += w
        check = (check >> 16) + (check & 0xFFFF)
        check = ~check & 0xFFFF
        return check
