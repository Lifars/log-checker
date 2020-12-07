# Log-Checker specification

## Purpose

- extract IOCs (observables) from logs
- check for extracted observables in Threat Intelligence feeds
- utility for Incident Response, Digital Forensics and Threat Hunting

## Features

- support for Windows EVTX logs
- support for text-based formats of log files
	- e.g. Linux auth.log and messages.log
- support for any plaintext files
	- observables should be parsed with Regular Expressions
- support for following observables:
	- IP addresses
	- domain names
	- hash values
- CSV and JSON output
- YETI as ThreatIntelligence backend
- configurable

## Tech specs

- developed in Python
- multiplatform
	- Windows version packed into one standalone executable
		- pyinstaller
	- Linux version could be Python script/module
- observable types:
	- IP addresses:
		- IPv4
		- IPv6
	- domain names
	- hash values:
		- MD5
		- SHA1
		- SHA256
- input:
	- plaintext files
		- observables are extracted with regular expressions
	- text-based log files
		- same as plaintext files
	- Windows EVTX files
		- could be parsed via evtx module for example
- extract observables and get Threat Intelligence data about them
	- minimize number of requests to YETI
	- create unique set of extracted observables and query YETI only once per unique observable
- Threat Intelligence data:
	- for each observable collect at least the following info from YETI:
		- value
		- tags
		- created (timestamp)
		- sources
- output
	- CSV and JSON formats
	- default is CSV
	- each entry should contain:
		- value,tags,created,sources,original_log
- options in config file:
	- URL of YETI instance
	- API key for YETI
	- output format
- options available via command-line arguments:
	- output format [CSV|JSON]
	- URL of YETI instance
	- API key for YETI
	- path to config file
		- if present, then override above options
	- path to evtx/log/plaintext file
	- output file
		- default is stdout
- runtime messages logged to stderr
- YETI backend
	- https://github.com/yeti-platform/yeti
- access via pyeti module
	- https://github.com/yeti-platform/pyeti
	- `pyeti.YetiApi(...).observable_search(...)`
