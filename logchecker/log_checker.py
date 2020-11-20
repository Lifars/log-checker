import json
import pyeti
import re


def check_log_file(file, url, key, output=None):
    addresses = parse_log_file(file)
    api = pyeti.YetiApi(url, api_key=key)
    for adr, logs in addresses.items():
        result = {"address": adr}
        result["yeti"] = api.observable_search(value=adr)
        result["logs"] = logs
        if output:
            json.dump(result, output, indent=4, sort_keys=True)
        else:
            print(json.dumps(result, indent=4, sort_keys=True))
            
    if output:
        output.close()


def parse_log_file(file):
    log = file.read().splitlines()
    addr_pattern = re.compile("(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
    addresses = {}
    for line in log:
        addr = addr_pattern.search(line)
        if addr:
            addr = addr.group(0)
            addresses.setdefault(addr, []).append(line)
    return addresses
