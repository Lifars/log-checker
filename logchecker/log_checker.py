import json
import pyeti
import re
import Evtx.Evtx as evtx
import os
import sys
import csv


def check_log_file(file, url, key, **kwargs):
    _, file_extension = os.path.splitext(file)
    print("reading file", file=sys.stderr)
    if file_extension == ".evtx":
        log = read_evtx_file(file)
    else:
        log = read_text_file(file)
    print("parsing file", file=sys.stderr)
    values = parse_log_file(log)
    print("looking in database", file=sys.stderr)
    results = []
    a = kwargs.get("all", False)
    api = pyeti.YetiApi(url, api_key=key)
    for val, logs in values.items():
        result = {"value": val}
        yeti = api.observable_search(value=val)
        if yeti:
            result["tags"] = yeti[0].get("tags", [])
            result["created"] = yeti[0].get("created", "")
            result["sources"] = yeti[0].get("sources", [])
        else:
            result["tags"] = []
            result["created"] = ""
            result["sources"] = []
        result["log"] = logs
        if yeti or a:
            results.append(result)

    print("writing results", file=sys.stderr)

    output = kwargs.get("output", None)
    c = kwargs.get("csv", None)
    if output:
        if c:
            fields = ["value", "tags", "created", "sources", "log"]
            results = flatten(map(unpack_logs, map(csv_row, results)))
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            writer.writerows(results)
        else:
            json.dump(results, output, indent=4, sort_keys=True)
        output.close()
    else:
        if c:
            fields = ["value", "tags", "created", "sources", "log"]
            results = flatten(map(unpack_logs, map(csv_row, results)))
            print(",".join(fields))
            for result in results:
                print(",".join(result.values()))
        else:
            print(json.dumps(results, indent=4, sort_keys=True))

    print("finished", file=sys.stderr)


def parse_log_file(log, **kwargs):
    addr_pattern = re.compile("(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
    domain_pattern = re.compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}")
    hash_pattern = re.compile("[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32}")
    a = kwargs.get("address", False)
    d = kwargs.get("domain", False)
    h = kwargs.get("hash", False)
    flags = a or d or h
    values = {}
    for line in log:
        if (not flags) or a:
            addr = addr_pattern.search(line)
            if addr:
                addr = addr.group(0)
                values.setdefault(addr, []).append(line)

        if (not flags) or d:
            dom = domain_pattern.search(line)
            if dom:
                dom = dom.group(0)
                values.setdefault(dom, []).append(line)

        if (not flags) or h:
            ha = hash_pattern.search(line)
            if ha:
                ha = ha.group(0)
                values.setdefault(ha, []).append(line)

    values.pop("schemas.microsoft.com", None)
    return values


def read_evtx_file(file):
    with evtx.Evtx(file) as f:
        log = list(map(evtx.Record.xml, f.records()))
    return log


def read_text_file(file):
    with open(file) as f:
        log = f.read().splitlines()
    return log


def dict_to_string(d):
    return " ".join(["{}:{}".format(key, val) for key, val in d.items()])


def list_to_string(li):
    return " ".join(li)


def csv_row(d):
    d["tags"] = list_to_string([dict_to_string(tag) for tag in d["tags"]])
    d["sources"] = list_to_string(d["sources"])
    return d


def unpack_logs(d):
    result = []
    for log in d["log"]:
        new = d.copy()
        new["log"] = log
        result.append(new)
    return result


def flatten(li):
    return [item for sublist in li for item in sublist]
