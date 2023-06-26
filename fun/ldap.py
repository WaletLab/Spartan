# sprawdzanie portow windowsowych
import port_scan
hostname = "107.178.246.171"
port = [[389]]
scanner = port_scan.Scanner(hostname, port)
result = scanner.execute()
print(scanner.scan_list)
