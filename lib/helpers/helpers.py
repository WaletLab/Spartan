class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    ITALIC = '\x1B[3m'
    STOP_ITALIC = '\x1B[0m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class Port:
    import re
    top_ports = [1, 5, 9, 7, 11, 13, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 49, 53, 70, 79, 80, 81, 88, 106, 110, 111,
                 113, 119, 135, 139, 143, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554,
                 587,
                 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
                 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5001, 5003, 5004, 5005, 5050, 5060, 5101,
                 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6346, 6347,
                 6666, 6697, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 32768, 32769, 32770, 32771, 32772,
                 32773, 32774, 32775, 32776, 32777, 32778, 32779,
                 49152, 49153, 49154, 49155, 1028, 49157, 49156, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175,
                 49176, 32803, 4662, 4672, 3689, 3690, 4333, 49400, 49401, 49402, 49403, 49404, 49405, 49406, 49407,
                 49408, 49409, 49410, 49411, 49412, 49413, 49414, 49415, 49416, 49417, 49418, 49419, 49420, 5901, 49421,
                 49422, 10000, 49425, 49426, 49427, 49423, 49429, 49430, 49431, 49432, 49433, 49434, 49435, 49436,
                 49437, 49438, 49439, 49440, 49441, 49442, 49443, 49444, 49445, 49446, 49447, 49448, 49449, 49450,
                 49451, 49452, 49453, 49454, 49455, 49456, 49457, 49458, 49459, 49460, 7000, 49424, 49428, 7070, 5555,
                 6646, 7937]

    def split_port_lists(lst, chunk_size):
        result = [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
        return result

    async def check_port(self, red, writer, addr, port):
        import socket
        from lib.helpers.cms_detector import detector
        def realm_check(response):
            import re
            match = re.search(r'realm="(.+)"', response.decode())
            return match

        def cms_check(response):
            import re
            data = {}
            # wordpress
            if b'wp-content' in response:
                data['wordpress'] = True
                pattern = r'\/wp-content\/plugins\/([^/]+)'
                plugins = re.findall(pattern, response.decode())
                data['plugins'] = plugins
            elif "joomla" in response.decode():
                data['joomla'] = True
                plugin_pattern = r'<h4 class="plugindesc-headline">(.+?)</h4>'
                plugins = re.findall(plugin_pattern, response.decode())
                data['plugins'] = plugins
            return data

        def get_server_info(data):
            try:
                import re
                # server info
                server_info = re.search(b"Server: (.+?)\r\n", data)
                # Extract content type information
                content_type_pattern = re.compile(rb'Content-Type: (.+?)\r\n')
                content_type_match = content_type_pattern.search(data)
                # Extract transfer encoding information
                transfer_encoding_pattern = re.compile(rb'Transfer-Encoding: (.+?)\r\n')
                transfer_encoding_match = transfer_encoding_pattern.search(data)
                return {"server": server_info.group(1).decode(),
                        "content": content_type_match.group(1).decode(),
                        "transfer": transfer_encoding_match.group(1).decode()
                        }
            except AttributeError:
                pass

        if port == 80:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((addr, port))
                sock.sendall(b"GET / HTTP/1.1\r\nHost: " + addr.encode() + b"\r\n\r\n")
                data = sock.recv(4096)
                if data:
                    d =detector(data)
                    cms_check = d.run()
                    realm = realm_check(data)
                    serv_info = get_server_info(data)
                    # cms_check = cms_check(data)
                    result = {
                        "serv_info": serv_info,
                        "realm": realm,
                        "cms_check": cms_check
                    }
                return result
