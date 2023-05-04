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
    top_1000 = [
        7, 9, 13, 21, 22, 23, 25, 37, 53, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 135, 139, 143, 179, 199, 389, 427, 443, 444, 445, 465, 513,
        514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
        1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
        2717, 3000, 3128, 3306, 3389, 3689, 3690, 4333, 4662, 4672, 4899, 5000, 5001, 5050,
        5060, 5101, 5190, 5357, 5432, 5555, 5631, 5666, 5800, 5900, 5901, 6000, 6001, 6646,
        6666, 7000, 7070, 7937, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
        32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32803, 49152,
        49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
        49400, 49401, 49402, 49403, 49404, 49405, 49406, 49407, 49408, 49409, 49410, 49411, 49412, 49413,
        49414, 49415, 49416, 49417, 49418, 49419, 49420, 49421, 49422, 49423, 49424, 49425, 49426, 49427,
        49428, 49429, 49430, 49431, 49432, 49433, 49434, 49435, 49436, 49437, 49438, 49439, 49440, 49441,
        49442, 49443, 49444, 49445, 49446, 49447, 49448, 49449, 49450, 49451, 49452, 49453, 49454, 49455,
        49456, 49457, 49458, 49459, 49460]

    def split_port_lists(lst, chunk_size):
        result = [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
        return result

    async def check_port(self, red,writer,addr,port):
        import re
        response = None
        if port == 80:
            # print("[*] Check port 80 [*]")
            query = f"GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n"
            writer.write(query.encode())
            await writer.drain()
            while True:
                resp = await red.read(4096)
                if not resp:
                    break
                response = resp
            writer.close()
            await writer.wait_closed()
            match = re.search(r'realm="(.+)"', response.decode())
            if match:
                return match.group(1)
            else:
                return False

    def script_execute(self, code):
        pass



#             "date": date_info.group(1).decode(),
            # "content": content_type_info.group(1).decode(),
            # "transfer": transfer_encoding_info.group(1).decode(),
            # "accpet-range": accept_ranges_info.group(1).decode(),
            # "vary": vary_info.group(1).decode()
            # }