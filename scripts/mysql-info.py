import socket

def get_mysql_info(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print("tu")
        sock.connect((host, port))
        sock.sendall(b"\x05\x00\x00\x00\x0a")
        data = sock.recv(1024)
        if len(data) < 9 or data[0] != 10 or data[1] != 0:
            return "Bad response from mysql server"
        protocol = data[0]
        version = data[2:data.index(b"\x00", 2)].decode("utf-8")
        status = data[-2]
        print("Protocol:", protocol)
        print("Version:", version)
        print("Status:", status)
        return version
    except socket.error as e:
        return False, e
    finally:
        sock.close()
# for x in result:
#     if x['port'] == 3306:
print(get_mysql_info('85.128.212.192',3306))