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
        "-c",
        "--config",
        help="Config file path",
        type=argparse.FileType("r"),
        required=True,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Log file path",
        type=lambda x: is_valid_file(parser, x),
        required=True,
    )
    parser.add_argument(
        "-o", "--output", help="Output file path", type=argparse.FileType("w+")
    )
    parser.add_argument(
        "-a",
        "--address",
        default=False,
        action="store_true",
        help="Search only for ip addresses",
    )
    parser.add_argument(
        "-d",
        "--domain",
        default=False,
        action="store_true",
        help="Search only for domains",
    )
    parser.add_argument(
        "-H",
        "--hash",
        default=False,
        action="store_true",
        help="Search only for hashes",
    )

    parser.add_argument(
        "-A",
        "--all",
        default=False,
        action="store_true",
        help="show all values in logs",
    )

    args = parser.parse_args()

    config = parse_config_file(args.config)
    check_log_file(
        args.file,
        config.url,
        config.key,
        output=args.output,
        address=args.address,
        domain=args.domain,
        hash=args.hash,
        all=args.all,
    )


def parse_config_file(file):
    config = configparser.ConfigParser()
    config.read_file(file)
    url = config.get("DEFAULT", "url")
    key = config.get("DEFAULT", "api_key")
    return Config(url, key)


if __name__ == "__main__":
    main()
