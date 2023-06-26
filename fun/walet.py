from concurrent.futures import ThreadPoolExecutor
import random
import ipaddress
# from Spar.lib.port_scan import Scanner
# from ..lib.helpersy.helpers import Port
from Spartan.lib.
from Spartan.lib.port_scan import Scanner
from time import perf_counter
from tqdm import tqdm
def gen_addr(ile):
    n = 0
    empty = []
    non = []
    no_empty = []
    ip_s = []
    while n <=ile:
        rand_ip_int = random.randrange(0x100_0000, 0xe000_0000)  # 1.0.0.0 - 224.0.0.0
        try:
            rand_ip = ipaddress.IPv4Address(rand_ip_int)

            if rand_ip.is_global:
                ip_s.append(str(rand_ip))
                # res = Scanner(str(rand_ip),[Port().walet_ports])
                # res.execute()
                # if res.scan_list != []:
                #     for x in res.scan_list:
                #         x['hostname'] = str(rand_ip)
                #         non.append(x)
                #         no_empty.append(rand_ip)
                # else:
                #     empty.append(rand_ip)
            n += 1
        except Exception as e:
            print(e)

    return ip_s
def fast_as_fuck(ips):
    def _skan(host):
        # res = Scanner(host,Port.split_port_lists([port for port in range(0,65536)],100)).execute()
        res = Scanner(host,[Port.walet_ports]).execute()
        # print(res)
        return res
    with ThreadPoolExecutor(max_workers = 520) as executor:
        start = perf_counter()
        results = executor.map(_skan, ips)
        stop = perf_counter()
        
        # print("timer skanera: {}".format(stop-start))
        
        # executor.shutdown(wait=True)
        # for x in results:
            # if x != []:
                # print(x)
        executor.shutdown(wait=True)
        print("timer skanera: {}".format(stop-start))
        return results
timer = perf_counter()
n = 200
t = gen_addr(n)
print("ile ip: {}".format(n))
print("mam ip skanuje")
y = fast_as_fuck(t)
for x in y:
    if x != []:
        print(x)
stop = perf_counter()
print(stop-timer)