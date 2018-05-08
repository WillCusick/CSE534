#!/usr/bin/env python3
# Authors: Matt Matero & Will Cusick
# Python Version: 3.5.2
import json
import sys

if len(sys.argv) < 2:
    print("Error: please provide a path to the HSTS preload list")
    sys.exit(1)

hsts_preload_path = sys.argv[1]
hsts_preload = {}
try:
    with open(hsts_preload_path) as hsts_preload_file:
        # Remove all the comments from the file
        cleaned_data = ""
        for line in hsts_preload_file:
            chomped_line = line.lstrip()
            if len(chomped_line) >= 2 and chomped_line.startswith("//"):
                continue
            cleaned_data += line

        hsts_preload = json.loads(cleaned_data)
except Exception as e:
    print(e)
    print("Error: could not open provided HSTS list")
    sys.exit(1)

sites = hsts_preload["entries"]

counter = 0
for site in sites:
    try:
        if site["mode"] == "force-https":
            counter += 1
    except:
        pass

print("Counted {} HSTS preloaded sites".format(counter))
