Logchecker
===========

Getting started
---------------

- make sure you have installed Python3
- logchecker depends on [pyeti](https://github.com/yeti-platform/pyeti) module which is not in PyPI, however, this module should be installed directly from GitHub with any of the methods described below

#### Install logchecker as a Python module and an executable script

- run `python3 setup.py install` on Linux or `setup.py install` on Windows
- run command `logchecker` or `python3 -m logchecker`

#### Use logchecker without installation

- install dependencies with `pip3 install -r requirements.txt`
- run command `python3 -m logchecker` from this directory

User guide
----------
Logchecker supports text-based log files, Windows EVTX logs and any plaintext file. Please note that working with EVTX files in Python is slow. It can be faster to use some other tool to convert EVTX file to text file and run `logchecker` on that file.

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
							file.If not specified, output is printed to STDOUT.
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
