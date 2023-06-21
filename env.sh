#!/bin/bash
#aktywacja srodowiska
source /home/dannyx/.virtualenvs/Spartan/bin/activate
python main.py --host $1 --port $2
