import json
import pyeti
import re
import Evtx.Evtx as evtx
import os
import sys


def check_log_file(file, url, key, output=None):
    _, file_extension = os.path.splitext(file)
    print("reading file", file=sys.stderr)
    if file_extension == ".evtx":
        log = read_evtx_file(file)
    else:
        log = read_text_file(file)
    print("parsing file", file=sys.stderr)
    addresses = parse_log_file(log)
    print("looking in database", file=sys.stderr)
    results = []
    api = pyeti.YetiApi(url, api_key=key)
    for adr, logs in addresses.items():
        result = {"address": adr}
        result["yeti"] = api.observable_search(value=adr)
        result["logs"] = logs
        results.append(result)

    print("writing results", file=sys.stderr)
    if output:
        json.dump(results, output, indent=4, sort_keys=True)
        output.close()
    else:
        print(json.dumps(results, indent=4, sort_keys=True))


def parse_log_file(log):
    addr_pattern = re.compile("(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
    addresses = {}
    for line in log:
        addr = addr_pattern.search(line)
        if addr:
            addr = addr.group(0)
            addresses.setdefault(addr, []).append(line)
    return addresses


def read_evtx_file(file):
    with evtx.Evtx(file) as f:
        log = list(map(evtx.Record.xml, f.records()))
    return log


def read_text_file(file):
    with open(file) as f:
        log = f.read().splitlines()
    return log
