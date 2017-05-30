#!/bin/sh
cd /home/xl/bill_dev
kill $(ps -ef | grep "[p]ython gx.py" | awk '{print $2}')
nohup python gx.py  >/dev/null 2>&1 &
