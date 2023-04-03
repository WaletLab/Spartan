
# Spartan

Python-based TCP/UDP port scanner project. It is designed to scan a target system for open ports using either TCP or UDP protocols. 

The project is named after the Spartan warriors who were known for their swift and efficient tactics, reflecting the scanner's ability to quickly scan ports and efficiently report the results.
Spartan is designed to be fast and efficient. It uses multi-threading to speed up the scanning process and reduce the time it takes to scan a target system. The scanner also provides the option to save the results of the scan to a file for later analysis.

To achieve full speed, you don't need a Docker image. You simply download the program and it's ready to use.
Additionally, thanks to custom scripts, you can fully automate your work and turn reconnaissance into a pure pleasure!

## Demo




    $ python main.py --host 127.0.0.1 --port 22
    ____                       _                 
    / ___|  _ __    __ _  _ __ | |_   __ _  _ __  
    \___ \ | '_ \  / _` || '__|| __| / _` || '_ \ 
    ___) || |_) || (_| || |   | |_ | (_| || | | |
    |____/ | .__/  \__,_||_|    \__| \__,_||_| |_|
        |_|                                    

        We make shit safe again 

    v0.0.2 created by dannyx-hub

    **************************************************
        Port Scanner 
    Spartan start to check ports on 127.0.0.1
    **************************************************
    Result for 127.0.0.1:
    found: 1
    TYPE      PORT  STATUS    SERVICE    INFO
    ------  ------  --------  ---------  ------------------------------------------
    tcp         22  OPEN      ssh        SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13

    Program end in: 0.06409557

## Features

- Scans all 65k ports in less than 3 seconds.
- Custom scripts support.
- Gui version(in progress)
- CMS detection


## Contributing

Contributions are always welcome!

Please let me know if you want support me in development!



## Authors

- [@dannyx-hub](https://www.github.com/dannyx-hub)

