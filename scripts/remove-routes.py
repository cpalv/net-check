#!/usr/bin/env python3
import os, stat, sys, subprocess
from datetime import datetime, timezone


ipversion="-4"

if len(sys.argv) == 3 and sys.argv[1] == "-6":
    ipversion="-6"

routes_file = sys.argv[2]

with open(routes_file, 'r') as rf:
    routes = rf.readlines()
    for route in routes:
        subprocess.run(f"ip {ipver} route del {route.strip()}", check=True)


exit()
