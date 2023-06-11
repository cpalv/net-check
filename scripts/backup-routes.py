#!/usr/bin/env python3
import os, stat, sys, subprocess
from datetime import datetime, timezone


ipversion="-4"
if len(sys.argv) == 2 and sys.argv[1] == "-6":
    ipversion="-6"

routes_file = ""
if ipversion == "-4":
    routes_file = "ip4-routes-{0}.rts".format(datetime.now().strftime("%s"))
else:
    routes_file = "ip6-routes-{0}.rts".format(datetime.now().strftime("%s"))

out = subprocess.run(f"ip {ipversion} route show".split(), capture_output=True)
with open(routes_file, 'w') as f:
    lines = out.stdout.splitlines()
    lines.reverse()
    # store in reverse order for easier processing later
    for line in lines:
        f.write(line.decode() + '\n')


exit()
