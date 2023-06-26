# import socket
# import time
# # print(result)
# for x in result:
#     if x['port'] == 22:
#         with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
#             try:
#              # Nawiązanie połączenia
#                 sock.connect((host, x['port']))

#                 # Odbiór danych z gniazda
#                 banner_data = sock.recv(1024)

#                 # Dekodowanie danych do postaci tekstowej
#                 banner = banner_data.decode('utf-8')

#                 # Wyświetlenie banneru SSH
#                 print("Banner SSH:")
#                 print(banner)
#             except Exception as e:
#                 print("Error: {} ".format(e))
import requests
import re
def check_wordpress(url):
    try:
        response = requests.get(url)
        if "wp-content" in response.text:
            print("Ta strona używa WordPressa.")
            pattern = r'<link[^>]+wp-content[^>]+plugins/([^/]+)/'
            plugins = re.findall(pattern, response)

            # Wyświetlanie znalezionych wtyczek
            if plugins:
                print("Znalezione wtyczki WordPressowe:")
                for plugin in plugins:
                    print(plugin)
            else:
                print("Nie znaleziono wtyczek WordPressowych.")
        else:
            print("Ta strona nie używa WordPressa.")

    except requests.exceptions.RequestException as e:
        print("Wystąpił błąd podczas żądania:", e)

# Przykładowe użycie:
url = "http://47.190.130.235:80"  # Zmień na adres URL strony do sprawdzenia
check_wordpress(url)