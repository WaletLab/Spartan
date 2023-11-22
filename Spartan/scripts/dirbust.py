
import socket
import requests
wordlist_path = "/home/dannyx/Desktop/Spartan/scripts/adds/basic_wordlist.txt"
print("dziala")
for x in result:
	if x['port'] == 80:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
			with open(wordlist_path,"r") as wordlist_file:
				lines = wordlist_file.readlines()
				for y in lines:
					rq = requests.get("http://"+host+":"+port+"/"+y)
					

