Log-checker
===========

Getting started
---------------

- make sure you have installed Python
- install [pyeti](https://github.com/yeti-platform/pyeti)
- run `python setup.py install` on Linux or `setup.py install` on Windows

User guide
----------
Log-checker supports text-based log files, Windows EVTX logs and any plaintext file. Please note that working with EVTX files in Python is slow. It can be faster to use some other tool to convert EVTX file to text file and run log-checker on that file.

#### Running in command line

Assume you want to check log file `auth.log`. Information needed to connect to YETI is in `config.ini`

The following command will find all IP addresses, domain names and hashes in `auth.log`, check them in YETI and print information (value, tags, created, sources, original log) to STDOUT in CSV format.


	logchecker -c config.ini -f auth.log
	
###### All options



	usage: logchecker [-h] [-c CONFIG] -f FILE [-o OUTPUT] [-a] [-d] [-H] [-A]
                   [-C | -j] [-u URL] [-k KEY]

	optional arguments:
	  -h, --help            show this help message and exit
	  -c CONFIG, --config CONFIG
							Config file path. Config file should contain url of
							YETI database, authorization key and output format. If
							it is present, it overrides --url, --key and
							--csv/--json options.
	  -f FILE, --file FILE  [REQUIRED] Log file path.
	  -o OUTPUT, --output OUTPUT
							Output file path. If file does not exist, creates new
							file. If not present, output is printed to stout If
							not specified, output is printed to STDOUT.
	  -a, --address         Search only for ip addresses. If none of the address,
							domain or hash flag is specified, it search for all
							mentioned.
	  -d, --domain          Search only for domains. If none of the address,
							domain or hash flag is specified, it search for all
							mentioned.
	  -H, --hash            Search only for hashes. If none of the address, domain
							or hash flag is specified, it search for all
							mentioned.
	  -A, --all             Show all values in logs. By default it shows only
							values which have record in database.
	  -C, --csv             Output in CSV format. This is default option.
	  -j, --json            Output in JSON format. By default output is in CSV
							format.
	  -u URL, --url URL     URL of YETI instance.
	  -k KEY, --key KEY     API key for YETI.




###### Configuration file

Configuration file should be in INI format. It should contain URL of YETI instance, API key for YETI and output format. 

Here is an example of configuration file:

	[DEFAULT]
	url = http://localhost:5000/api/
	api_key = abc123
	output_format = json

**Note:** Values from configuration file override values from command line arguments.

#### Importing as python package

Package `logchecker` has one module `log_checker` with folowing functions:

`check_log_file(file, url, key, **kwargs):`
Extracts IP addresses, domain names and hashes from *file* and check them in YETI. Prints output in CSV format. Output contains value, tags, created, sources  and original log.
Parameters:
- `file` \- path of log file
- `url` \- url of YETI instance
- `key` \- API key for YETI
- `output` \- Output file handler. If present, print output to file instead of STDOUT
- `address` \- If true, extracts only IP addresses
- `domain` \- If true, extracts only domain names
- `hash` \- If true, extracts only hashes
- `all` \- If true, prints all observables even if they have no record in YETI
- `csv` \- If true, output is in CSV format
- `json` \- If true, output is in JSON format

`parse_log_file(log, **kwargs):`
Extracts IP addresses, domain names and hashes from *log*. Returns list of dictionaries with observables and corresponding lines from *log*.
Parameters:
- `log` \- Log file handler
- `address` \- If true, extracts only IP addresses
- `domain` \- If true, extracts only domain names
- `hash` \- If true, extracts only hashes
