import argparse
import configparser
import collections
import os

from logchecker.log_checker import check_log_file

Config = collections.namedtuple("Config", ["url", "key"])


def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", help="Config file path", type=argparse.FileType("r"), required=True
    )
    parser.add_argument(
        "-f",
        help="Log file path",
        type=lambda x: is_valid_file(parser, x),
        required=True,
    )
    parser.add_argument("-o", help="Output file path", type=argparse.FileType("w+"))
    args = parser.parse_args()

    config = parse_config_file(args.c)
    check_log_file(args.f, config.url, config.key, args.o)


def parse_config_file(file):
    config = configparser.ConfigParser()
    config.read_file(file)
    url = config.get("DEFAULT", "url")
    key = config.get("DEFAULT", "api_key")
    return Config(url, key)


if __name__ == "__main__":
    main()
