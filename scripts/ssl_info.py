import ssl
import socket
from lib.helpers import color 

for x in result:
    if x['port'] == 443:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                with context.wrap_socket(sock,server_hostname = host) as ssl_sock:
                    ssl_sock.connect((host,x['port']))
                    cert = ssl_sock.getpeercert()
                    if cert != {}:
                        cert_info = dict(
                            Subject = cert["subject"],
                            Issuer = cert['issuer'],
                            Valid_from = cert['notBefore'],
                            Valid_until = cert['notAfter'],
                            Serial_number = cert['serialNumber']
                        )
                        print("\nSSL info for "+color.BOLD+f"{host}:\n"+color.END)
                        for k,v in enumerate(cert_info):
                            print(v+": "+str(cert_info[v]))
                    else:
                        raise Exception("blad")
            except Exception as e:
                print(e)