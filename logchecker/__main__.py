import argparse
import configparser
import collections

Config = collections.namedtuple("Config", ["url", "key"])



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", help="Config file path", type=argparse.FileType("r"), required=True
    )
    parser.add_argument(
        "-f", help="Log file path", type=argparse.FileType("r"), required=True
    )
    args = parser.parse_args()

    config = parse_config_file(args.c)

def parse_config_file(file):
    config = configparser.ConfigParser()
    config.read_file(file)
    url = config.get("DEFAULT", "url")
    key = config.get("DEFAULT", "api_key")
    return Config(url, key)




if __name__ == "__main__":
    main()
