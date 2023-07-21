import socket
for x in result:
    if x['port'] = 443:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, x['port']))

        s.sendall(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x00\x00\x20\xcc\xa8\xcc\xa9\xc0\x2f\xc0\x30\xc0\x2b\xc0\x2c\xc0\x13\xc0\x09\xc0\x14\xc0\x0a\x00\x9c\x00\x9d\x00\x2f\x00\x35\xc0\x12\x00\x0a\x01\x00\x00\x58\x00\x00\x00\x18\x00\x16\x00\x00\x13\x65\x78\x61\x6d\x70\x6c\x65\x2e\x75\x6c\x66\x68\x65\x69\x6d\x2e\x6e\x65\x74\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x0d\x00\x12\x00\x10\x04\x01\x04\x03\x05\x01\x05\x03\x06\x01\x06\x03\x02\x01\x02\x03\xff\x01\x00\x01\x00\x00\x12\x00\x00")
        raw = s.recv(4096)

        import struct

        u_iter = 0
        def unpack_next(fmt):
            sz = struct.calcsize(fmt)
            global u_iter
            val = struct.unpack(fmt, raw[u_iter:u_iter+sz])
            u_iter += sz
            return val

        record_type = unpack_next("B")[0]
        record_protocol_version_major, record_protocol_version_minor = unpack_next("B")[0], unpack_next("B")[0]
        record_data_length = unpack_next(">H")[0]
        print("record_type", record_type)
        print("record_protocol_version", (record_protocol_version_major, record_protocol_version_minor))
        print("record_data_length", record_data_length)

        handshake_type = unpack_next("B")[0]
        unpack_next("B")
        handshake_data_length = unpack_next(">H")[0]
        print("handshake_type", handshake_type)
        print("handshake_data_length", handshake_data_length)

        server_version_major, server_version_minor = unpack_next("B")[0], unpack_next("B")[0]
        random = unpack_next("32B")
        session_id_length = unpack_next("B")[0]
        session_id = unpack_next(str(session_id_length) + "B")
        cipher_suite = unpack_next("B")[0], unpack_next("B")[0]
        compression_method = unpack_next("B")[0]
        extensions_length = unpack_next(">H")[0]
        extensions = []

        end = u_iter + extensions_length
        while u_iter < end:
            type_ = unpack_next(">H")[0]
            info_length = unpack_next(">H")[0]
            info = unpack_next(str(info_length) + "B")
            extensions.append((type_, info_length, info))

        print("sever_version", (server_version_major, server_version_minor))
        print("random", random)
        print("session_id_length", session_id_length)
        print("session_id", session_id)
        print("cipher_suite", cipher_suite)
        print("compression_method", compression_method)
        print("extensions_length", extensions_length)
        print("extensions")
        for ext in extensions:
            print(f"\t{ext}")

        ja3s = str(server_version_major << 8 | server_version_minor) + "," + str(cipher_suite[0] << 8 | cipher_suite[1]) + ","
        ja3s += "-".join([str(e[0]) + "-" + str(e[1]) + "-".join([str(v) for v in e[2]]) for e in extensions])
        import hashlib
        ja3s = hashlib.md5(ja3s.encode("ascii")).hexdigest()
        print("\nJA3S", ja3s)