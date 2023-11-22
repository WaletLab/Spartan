import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    for x in result.keys():
        if x == 22:
            try:
                sock.connect((host, x))
                sock.sendall(b'SSH-2.0-Test\r\n')
                resp = sock.recv(1024)
                print(resp.decode('utf-8','ignore'))
            except Exception as e:
                print(e)
                