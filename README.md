The Python script `greynoise.py` makes use of GreyNoise's [public/alpha API](https://github.com/GreyNoise-Intelligence/api.greynoise.io) to perform its operations.

## Requirements
* Python 3.5 or higher
* Have the Python packages `Requests` and `PyYAML` installed

## Installation
1. `git clone https://github.com/marcusbakker/Greynoise`
2. `pip install -r requirements.txt`

## Usage
The script has the following features:
* Query for all tags associated with a given IP or CIDR IP range: `-ip`
* Query all IPs/CIDR ranges within the provided file: `-f FILE, --file FILE`
* Get a list of all GreyNoise\'s current tags: `-l, --list`
* Get all IPs and its associated metadata for the provided tag: `-t TAG_ID, --tag TAG_ID`
* Identify the noise and add context on the noise in the provided CSV file. The output filename has 'greynoise_' as prefix. First argument should point to the CSV file and the second argument to the index value (starting at 1) at which the IP address is located in the CSV file. `--csv CSV_FILE IP_COLUMN_INDEX`
* Output the result to a file using the argument `-o FILE_LOCATION, --output FILE_LOCATION`. Default file format is txt and other supported file formats are CSV and JSON: `--format {txt,csv,json}`
* Hide results for IP addresses which have the status "unknown" using the argument: `-u, --hide-unknown`
* GreyNoise's response for an IP address is cached for 24 hours.
  * Expire all entries within the IP cache: `--cache-expire`
  * Set the IP cache timeout in seconds: `--cache-timeout SECONDS`
  * The default cache timeout can be changed within `config.yaml` using the setting `cache_timeout`
* Set an API key which enables you to receive more than 500 results per query: `-k KEY, --key KEY`. The API key can also be permanently set within `config.yaml`

## Configuration file
The configuration file `config.yaml` contains the following three settings:
* `api_key`: Permanently set an API key which enables you to receive more than 500 results per query.
* `cache_timeout`: Set the cache timeout in seconds. The default is 24 hours.
* `tags`: Adding or modifying GreyNoise's tag IDs and corresponding names.
