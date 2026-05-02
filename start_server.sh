#!/bin/bash
cd /home/analystai/.opencode/bin/dashboard
exec /usr/bin/python3 server.py >> server.log 2>&1 &