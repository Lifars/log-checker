#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Logchecker tool for scanning log files against YETI Threat Intelligence Repository.
By LIFARS

This code is licensed under MIT license (see LICENSE for details)
"""

__version__ = "0.8"

__author__ = "LIFARS LLC"
__copyright__ = "Copyright (c) 2020,2021 LIFARS LLC"
__credits__ = ["LIFARS LLC"]
__license__ = "MIT"
__maintainer__ = "LIFARS LLC"
__status__ = "Production"

import argparse
import collections
import configparser
import csv
import json
import os
import re
import sys

import Evtx.Evtx as evtx

import pyeti

Config = collections.namedtuple("Config", ["url", "key", "output"])


def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        help="Config file path. Config file should contain url of YETI database,"
        " authorization key and output format. If it is present, it overrides"
        " --url, --key and  --csv/--json options.",
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        "-f",
        "--file",
        help="[REQUIRED] Log file path.",
        type=lambda x: is_valid_file(parser, x),
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path. If file does not exist, creates new file."
        "If not specified, output is printed to STDOUT.",
        type=argparse.FileType("w+"),
    )
    parser.add_argument(
        "-a",
        "--address",
        default=False,
        action="store_true",
        help="Search only for ip addresses. If none of the address, "
        "domain or hash flag is specified, it search for all mentioned.",
    )
    parser.add_argument(
        "-d",
        "--domain",
        default=False,
        action="store_true",
        help="Search only for domains. If none of the address, "
        "domain or hash flag is specified, it search for all mentioned.",
    )
    parser.add_argument(
        "-H",
        "--hash",
        default=False,
        action="store_true",
        help="Search only for hashes. If none of the address, "
        "domain or hash flag is specified, it search for all mentioned.",
    )
    parser.add_argument(
        "-A",
        "--all",
        default=False,
        action="store_true",
        help="Show all values in logs. By default it shows only values "
        "which have record in database.",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-C",
        "--csv",
        default=False,
        action="store_true",
        help="Output in CSV format. This is default option.",
    )
    group.add_argument(
        "-j",
        "--json",
        default=False,
        action="store_true",
        help="Output in JSON format. By default output is in CSV format.",
    )

    parser.add_argument("-u", "--url", help="URL of YETI instance.", type=str)
    parser.add_argument("-k", "--key", help="API key for YETI.", type=str)

    args = parser.parse_args()
    if not (args.config or args.url):
        parser.error(
            "Missing URL of YETI. Use --url URL or add config file using --config CONFIG"
        )

    url = args.url
    key = args.key
    csv = args.csv
    json = args.json
    if args.config:
        url, key, outf = parse_config_file(args.config)
        if outf.lower() == "json":
            json = True
            csv = False
        elif outf.lower() == "csv":
            json = False
            csv = True
        else:
            print("Unsupported output format. Using default", file=sys.stderr)
            json = False
            csv = True

    check_log_file(
        args.file,
        url,
        key,
        output=args.output,
        address=args.address,
        domain=args.domain,
        hash=args.hash,
        all=args.all,
        csv=csv,
        json=json,
    )


def parse_config_file(file):
    config = configparser.ConfigParser()
    config.read_file(file)
    url = config.get("DEFAULT", "url")
    key = config.get("DEFAULT", "api_key")
    output = config.get("DEFAULT", "output_format")
    return Config(url, key, output)


def check_log_file(file, url, key, **kwargs):
    _, file_extension = os.path.splitext(file)
    print("reading file", file=sys.stderr)
    if file_extension == ".evtx":
        log = __read_evtx_file(file)
    else:
        log = __read_text_file(file)
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
        result["original_log"] = logs
        if yeti or a:
            results.append(result)

    print("writing results", file=sys.stderr)

    ret = kwargs.get("ret", False)
    if ret:
        return results

    output = kwargs.get("output", None)
    if not output:
        output = sys.stdout
    j = kwargs.get("json", False)
    if j:
        json.dump(results, output, indent=4, sort_keys=True)
    else:
        fields = ["value", "tags", "created", "sources", "original_log"]
        results = __flatten(map(__unpack_logs, map(__csv_row, results)))
        writer = csv.DictWriter(output, fieldnames=fields, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(results)
    outfh = kwargs.get("output", None)
    if outfh:
        outfh.close()

    print("finished", file=sys.stderr)


def parse_log_file(log, **kwargs):
    addr_pattern = re.compile("(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
    ipv6_pattern = re.compile(
        "([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
        "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|"
        "::(ffff(:0{1,4})?:)?"
        "((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}"
        "(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|"
        "([0-9a-fA-F]{1,4}:){1,4}:"
        "((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}"
        "(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|"
        ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
        "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
        "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
        "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
        "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
        "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
        "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        "([0-9a-fA-F]{1,4}:){1,7}:"
    )
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

            addr = ipv6_pattern.search(line)
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


def __read_evtx_file(file):
    with evtx.Evtx(file) as f:
        log = list(map(evtx.Record.xml, f.records()))
    return log


def __read_text_file(file):
    with open(file) as f:
        log = f.read().splitlines()
    return log


def __dict_to_string(d):
    return " ".join(["{}:{}".format(key, val) for key, val in d.items()])


def __list_to_string(li):
    return " ".join(li)


def __csv_row(d):
    d["tags"] = __list_to_string([__dict_to_string(tag) for tag in d["tags"]])
    d["sources"] = __list_to_string(d["sources"])
    return d


def __unpack_logs(d):
    result = []
    for log in d["original_log"]:
        new = d.copy()
        new["original_log"] = log
        result.append(new)
    return result


def __flatten(li):
    return [item for sublist in li for item in sublist]


if __name__ == "__main__":
    main()
