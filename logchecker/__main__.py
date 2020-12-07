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
        help="Config file path. Config file should contain url of YETI database, authorization key and output format. If it is present, it overrides --url, --key and  --csv/--json options.",
        type=argparse.FileType("r")
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
        help="Output file path. If file does not exist, creates new file. If not present, output is printed to stout "
        "If not specified, output is printed to stout.",
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
    parser.add_argument(
        "-C",
        "--csv",
        default=True,
        help="Output in csv format. This is default option.",
    )
    parser.add_argument(
        "-j",
        "--json",
        default=False,
        action="store_true",
        help="Output in json format. By default output is in CSV format.",
    )
    parser.add_argument(
        "-u",
        "--url",
        help="URL of YETI instance.",
        type=str
    )
    parser.add_argument(
        "-k",
        "--key",
        help="API key for YETI.",
        type=str
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
        csv=args.csv,
    )


def parse_config_file(file):
    config = configparser.ConfigParser()
    config.read_file(file)
    url = config.get("DEFAULT", "url")
    key = config.get("DEFAULT", "api_key")
    return Config(url, key)


if __name__ == "__main__":
    main()
