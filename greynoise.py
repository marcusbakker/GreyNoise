#!/usr/bin/env python

import re
import requests
import ipaddress
from collections import OrderedDict
from datetime import datetime as dt
import argparse
import os
import pickle
import csv
import yaml
import sys
import json


VERSION = '0.1'
CONFIG_FILE = 'config.yaml'
API_KEY = None
HIDE_UNKNOWN = False
IPV4_ADDRESS = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
TAGS = {}

CSV_HEADER_ENRICHMENT = ['Noise', 'rDNS', 'ASN', 'Organisation', 'Tag', 'Category', 'Intention', 'Confidence',
                         'Datacenter', 'Operating_system', 'Link', 'Tor']
CSV_HEADER_LIST = ['Tag_ID', 'Tag_name']
CSV_HEADER_IP = ['IP', 'Noise', 'rDNS', 'rDNS_parent', 'ASN', 'Organisation', 'Tag_id', 'Tag_name', 'Category',
                 'Intention', 'Confidence', 'Datacenter', 'Operating_system', 'Link', 'Tor', 'First_seen',
                 'Last_updated']

CACHE_TIMEOUT = 60*60*24  # 24 hours, is here as a backup if not within config.yaml
CACHE_LOCATION = '.api_ip_cache'
CACHE_MODIFIED = False  # is used to determine if a new version of the ip cache should be written to disk
# structure of the dict: {ip: {'date': datetime, raw:{} }}
ip_cache = {}

URL_API_IP = 'http://api.greynoise.io:8888/v1/query/ip'
URL_API_LIST = 'http://api.greynoise.io:8888/v1/query/list'
URL_API_TAG = 'http://api.greynoise.io:8888/v1/query/tag'

INDENT = 15
COLUMN_NAME = 40
COLUMN_CONFIDENCE = 14
COLUMN_CATEGORY = 12
COLUMN_INTENTION = 12
COLUMN_COUNT = 8
COLUMN_FIRST_SEEN = 14
COLUMN_LAST_UPDATED = 14

processed_IPs = set()
session = None


def init_menu():
    menu_parser = argparse.ArgumentParser(description='Query GreyNoise',
                                          epilog='https://github.com/marcusbakker/GreyNoise')
    group = menu_parser.add_mutually_exclusive_group()

    group.add_argument('-ip', type=str, help='query for all tags associated with a given IP or CIDR IP range', metavar='IP')
    group.add_argument('-f', '--file', help='query all IPs/CIDR ranges within the provided file', metavar='FILE')
    group.add_argument('-l', '--list', help='get a list of all GreyNoise\'s current tags', action='store_true')
    group.add_argument('-t', '--tag', help='get all IPs and its associated metadata for the provided tag', metavar='TAG_ID')
    group.add_argument('--csv', help='identify the noise and add context on the noise in the provided CSV file. '
                                     'The output filename has \'greynoise_\' as prefix',
                       metavar=('CSV_FILE', 'IP_COLUMN_INDEX'), nargs=2)
    menu_parser.add_argument('-o', '--output', help='output the result to a file (default format = txt)',
                             metavar='FILE_LOCATION')
    menu_parser.add_argument('--format', help='specify the format of the output file', choices=['txt', 'csv', 'json', ], default='txt')
    menu_parser.add_argument('-u', '--hide-unknown', help='hide results for IP addresses which have the status "unknown"'
                             , action='store_true')
    menu_parser.add_argument('--cache-expire', help='expire all entries within the IP ip cache', action='store_true')
    menu_parser.add_argument('--cache-timeout', help='set the IP ip cache timeout in seconds (default = 24 hours)',
                             metavar='SECONDS')
    menu_parser.add_argument('-k', '--key', help='API key', metavar='KEY')
    menu_parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    return menu_parser


# load the YAML config and set some variables
def load_config():
    global CACHE_TIMEOUT
    global TAGS
    global API_KEY

    with open(CONFIG_FILE, 'r') as yaml_file:
        config = yaml.load(yaml_file)

    API_KEY = config['api_key']
    CACHE_TIMEOUT = config['cache_timeout']
    TAGS = config['tags']


# define the length for the column tag name
def initialize_column_name():
    global COLUMN_NAME
    COLUMN_NAME = 0

    # v = tag name
    for k, v in TAGS.items():
        tag_length = len(v)
        if tag_length > COLUMN_NAME:
            COLUMN_NAME = tag_length

    COLUMN_NAME += (INDENT + 3)


# remove cached items older then CACHE_TIMEOUT
def purge_cache():
    global ip_cache
    global CACHE_MODIFIED
    cache_purged = dict(ip_cache)
    now = dt.now()

    for k, v in ip_cache.items():
        if (now-v['date_added']).total_seconds() >= CACHE_TIMEOUT:
            del cache_purged[k]
            CACHE_MODIFIED = True

    ip_cache = dict(cache_purged)


def expire_cache():
    if os.path.exists(CACHE_LOCATION):
        os.remove(CACHE_LOCATION)


# load the ip_cache from disk
def initialize_cache():
    global ip_cache
    if os.path.exists(CACHE_LOCATION):
        with open(CACHE_LOCATION, 'rb') as f:
            ip_cache = pickle.load(f)

        purge_cache()


# save the ip_cache to disk
def save_cache():
    if CACHE_MODIFIED:
        with open(CACHE_LOCATION, 'wb') as f:
            pickle.dump(ip_cache, f)


# structure of the data: {ip: {'date': datetime, raw:{} }}
def add_to_cache(ip, raw_data):
    global ip_cache
    global CACHE_MODIFIED
    if ip not in ip_cache:
        now = dt.now()
        ip_cache[ip] = {'date_added': now, 'raw': raw_data}
        CACHE_MODIFIED = True


# dict structure: {'item': count}
def add_record_item_to_dict(item, d):
    if item != '':
        if item in d:
            d[item] += 1
        else:
            d[item] = 1

    return d


# convert Greynoise's date to a datetime object
def get_datetime(date_string, full_date=False):
    date_string = re.sub('Z$', '', date_string)
    if '.' in date_string:
        date = dt.strptime(re.sub('\.[0-9]+$', '', date_string), '%Y-%m-%dT%H:%M:%S')
    else:
        date = dt.strptime(date_string, '%Y-%m-%dT%H:%M:%S')
    if full_date:
        return date.strftime('%Y-%m-%d %H:%M:%S')
    else:
        return date.strftime('%Y-%m-%d')


# dict structure: {'tag_id': {'tag_name': '...', 'confidence': '...', 'category': '...', 'intention': '...',
#                 'first_seen': '...', 'last_updated': '...', 'count': '...'} }
def add_tag(tag_id, confidence, category, intention, first_seen, last_updated, dic):
    if tag_id in dic:
        dic[tag_id]['count'] += 1
    else:
        tag_name = tag_id
        if tag_id in TAGS:
            tag_name = TAGS[tag_id]

        first_seen_str = get_datetime(first_seen)
        last_updated_str = get_datetime(last_updated)

        dic[tag_id] = {'tag_name': tag_name, 'confidence': confidence, 'category': category, 'intention': intention,
                       'first_seen': first_seen_str, 'last_updated': last_updated_str, 'count': 1}
    return dic


def print_tags(d):
    print('Tags:')
    format_string = '{:<'+str(COLUMN_NAME)+'s}{:<'+str(COLUMN_CONFIDENCE)+'s}{:<'+str(COLUMN_CATEGORY)+'s}{:<' + \
                    str(COLUMN_INTENTION)+'s}{:<'+str(COLUMN_COUNT)+'s}{:<'+str(COLUMN_FIRST_SEEN)+'s}{:<' + \
                    str(COLUMN_LAST_UPDATED)+'s}'

    print(format_string.format(' ' * INDENT + 'Name', 'Confidence', 'Category', 'intention', 'Count', 'First seen',
                               'Last updated'))

    print(' ' * INDENT + '-' * (COLUMN_NAME + COLUMN_CONFIDENCE + COLUMN_CATEGORY + COLUMN_INTENTION + COLUMN_COUNT +
                                COLUMN_FIRST_SEEN + COLUMN_LAST_UPDATED - INDENT - 2))

    od = OrderedDict(sorted(d.items(), key=lambda x: x[1]['count'], reverse=True))

    for tag, v in od.items():
        print(format_string.format(' ' * INDENT + v['tag_name'], v['confidence'], v['category'], v['intention']
                                   , str(v['count']), v['first_seen'], v['last_updated']))


def print_single_record_item(name, record_item, colon=False):
    if record_item != '':
        if colon:
            name += ':'
        l_name = len(name)
        for i in range(l_name, INDENT):
            name += ' '

        print(name + str(record_item))


def print_multi_record_item(name, record_item):
    name += ':'

    # indent
    name_length = len(name)
    for i in range(name_length, INDENT):
        name += ' '

    printed_name = False
    if len(record_item) > 1:
        indent = 0
        for record, count in record_item.items():
            if not printed_name:
                printed_name = True
                metadata = '[' + str(count) + '][last seen]  '
                indent = len(metadata)-3
                print(name + metadata + record)
            else:
                len_count = len(str(count))
                print_single_record_item('', '[' + str(count) + '] ' + ' '*(indent-len_count) + record)
    elif len(record_item) == 1:
        item = list(record_item.keys())[0]
        print_single_record_item(name, str(item))


# read a file from disk
def read_file(file_location):
    if os.path.exists(file_location):
        with open(file_location, 'r') as f:
            return f.readlines()
    else:
        print('[!] file does not exist')


def print_ip_query(data, single_ip):
    if data:
        len_records = 0

        if 'records' in data:
            len_records = len(data['records'])

        if len_records == 0 and not HIDE_UNKNOWN:
            print_single_record_item('IP', data['ip'], colon=True)
            print_single_record_item('Status', data['status'], colon=True)

        if len_records > 0:
            print_single_record_item('IP', data['ip'], colon=True)

            records = data['records']
            tags = OrderedDict()
            ASN = OrderedDict()
            reverse_DNS = OrderedDict()
            datacenter = OrderedDict()
            operating_system = OrderedDict()
            link = OrderedDict()
            organisation = OrderedDict()
            tor = OrderedDict()

            for r in records:
                tags = add_tag(r['name'], r['confidence'], r['category'], r['intention'], r['first_seen'],
                               r['last_updated'], tags)
                reverse_DNS = add_record_item_to_dict(r['metadata']['rdns'], reverse_DNS)
                ASN = add_record_item_to_dict(r['metadata']['asn'], ASN)
                organisation = add_record_item_to_dict(r['metadata']['org'], organisation)
                datacenter = add_record_item_to_dict(r['metadata']['datacenter'], datacenter)
                operating_system = add_record_item_to_dict(r['metadata']['os'], operating_system)
                link = add_record_item_to_dict(r['metadata']['link'], link)
                tor = add_record_item_to_dict(r['metadata']['tor'], tor)

            print_multi_record_item('rDNS', reverse_DNS)
            print_multi_record_item('ASN', ASN)
            print_multi_record_item('Organisation', organisation)
            print_multi_record_item('Datacenter', datacenter)
            print_multi_record_item('OS', operating_system)
            print_multi_record_item('Link', link)
            print_multi_record_item('TOR', tor)
            print_single_record_item('Records', '[' + str(len_records) + ']', colon=True)
            print_tags(tags)

        if not single_ip and not (len_records == 0 and HIDE_UNKNOWN):
            print('\n' + '=' * (COLUMN_NAME + COLUMN_CONFIDENCE + COLUMN_CATEGORY + COLUMN_INTENTION + COLUMN_COUNT +
                                COLUMN_FIRST_SEEN + COLUMN_LAST_UPDATED - 2))


# query Greynloise for an IP
def query_ip(ip, single_ip=True, source_csv=False):
    if IPV4_ADDRESS.match(ip):
        global session
        if not session:
            session = requests.Session()

        if ip not in processed_IPs:
            processed_IPs.add(ip)

            # get the data from the ip_cache if possible
            if ip in ip_cache:
                data = ip_cache[ip]['raw']
            else:
                post_data = {'ip': ip}
                if API_KEY is not None:
                    post_data['key'] = API_KEY

                try:
                    response = session.post(URL_API_IP, data=post_data)
                except Exception as e:
                    print('[!] error:\n', e)
                    return
                data = response.json()

            add_to_cache(ip, data)
            return data
        else:
            if source_csv:
                return ip_cache[ip]['raw']
            else:
                return None
    else:
        print('[!] invalid ip: '+ip)
        if not single_ip:
            print('\n' + '=' * (COLUMN_NAME + COLUMN_CONFIDENCE + COLUMN_CATEGORY + COLUMN_INTENTION + COLUMN_COUNT +
                                COLUMN_FIRST_SEEN + COLUMN_LAST_UPDATED - 2))
        return None


def print_tag_list(data):
    if data:
        tags = sorted(data['tags'])

        tag_length = 0
        for tag in tags:
            tmp_tag_length = len(tag)
            if tmp_tag_length > tag_length:
                tag_length = l
        format_string = '{:<' + str(tag_length+3) + 's}{:<' + str(tag_length+3) + 's}'

        print(format_string.format('Tag ID', 'Tag name'))
        print('-'*(tag_length*2+6))

        for tag in tags:
            tag_name = ''
            if tag in TAGS:
                tag_name = TAGS[tag]
            print(format_string.format(tag, tag_name))


# query Greynloise for the tag list
def query_tag_list():
    global session
    if not session:
        session = requests.Session()

    try:
        response = session.get(URL_API_LIST)
    except Exception as e:
        print('[!] error:\n', e)
        return

    data = response.json()
    if data['status'] == 'ok':
        return data
    else:
        print('[!] status is not "ok"')
        return None


def print_tag_records(data):
    if 'records' not in data:
        print('No results for tag: ', data['tag'])
        return

    records = data['records']

    print_single_record_item('Tag', data['tag'], colon=True)
    print_single_record_item('Records', '[' + str(data['returned_count']) + ']', colon=True)
    print('\n' + '=' * (COLUMN_NAME + COLUMN_CONFIDENCE + COLUMN_CATEGORY + COLUMN_INTENTION + COLUMN_COUNT +
                        COLUMN_FIRST_SEEN + COLUMN_LAST_UPDATED - 2))

    for r in records:
        print_single_record_item('IP', r['ip'], colon=True)
        print_single_record_item('rDNS', r['metadata']['rdns'], colon=True)
        print_single_record_item('ASN', r['metadata']['asn'], colon=True)
        print_single_record_item('Organisation', r['metadata']['org'], colon=True)
        print_single_record_item('Datacenter', r['metadata']['datacenter'], colon=True)
        print_single_record_item('OS', r['metadata']['os'], colon=True)
        print_single_record_item('Link', r['metadata']['link'], colon=True)
        print_single_record_item('TOR', r['metadata']['tor'], colon=True)

        print('\n' + '=' * (COLUMN_NAME + COLUMN_CONFIDENCE + COLUMN_CATEGORY + COLUMN_INTENTION + COLUMN_COUNT +
                            COLUMN_FIRST_SEEN + COLUMN_LAST_UPDATED - 2))


# query Greynloise for a specific tag
def query_tag(tag):
    global session
    if not session:
        session = requests.Session()

    post_data = {'tag': tag}
    if API_KEY is not None:
        post_data['key'] = API_KEY

    try:
        response = session.post(URL_API_TAG, data=post_data)
    except Exception as e:
        print('[!] error:\n', e)
        return
    data = response.json()
    return data


def add_record_item_to_set(item, s):
    if item != '':
        s.add(item)
    return s


def get_enriched_csv_row(row, data):
    if data:
        len_records = 0

        row.append(data['status'])

        if 'records' in data:
            len_records = len(data['records'])

        if len_records > 0:
            records = data['records']

            reverse_DNS = set()
            ASN = set()
            organisation = set()
            tag = set()
            category = set()
            intention = set()
            datacenter = set()
            confidence = set()
            operating_system = set()
            link = set()
            tor = set()

            for r in records:
                reverse_DNS = add_record_item_to_set(r['metadata']['rdns'], reverse_DNS)
                ASN = add_record_item_to_set(r['metadata']['asn'], ASN)
                organisation = add_record_item_to_set(r['metadata']['org'], organisation)
                tag = add_record_item_to_set(r['name'], tag)
                category = add_record_item_to_set(r['category'], category)
                intention = add_record_item_to_set(r['intention'], intention)
                confidence = add_record_item_to_set(r['confidence'], confidence)
                datacenter = add_record_item_to_set(r['metadata']['datacenter'], datacenter)
                operating_system = add_record_item_to_set(r['metadata']['os'], operating_system)
                link = add_record_item_to_set(r['metadata']['link'], link)
                tor = add_record_item_to_set(str(r['metadata']['tor']), tor)

            row.append(', '.join(reverse_DNS))
            row.append(', '.join(ASN))
            row.append(', '.join(organisation))
            row.append(', '.join(tag))
            row.append(', '.join(category))
            row.append(', '.join(intention))
            row.append(', '.join(confidence))
            row.append(', '.join(datacenter))
            row.append(', '.join(operating_system))
            row.append(', '.join(link))
            row.append(', '.join(tor))

    return row


def process_csv_file(cmd_args, output_to_file):
    csv_file_path = cmd_args[0]
    ip_column_idx = int(cmd_args[1]) - 1
    csv_header = []
    csv_column_amount = 0
    response_data = []

    if os.path.exists(csv_file_path):
        with open(csv_file_path, newline='') as csvfile:
            # sniff into 10KB of the file to get its dialect
            dialect = csv.Sniffer().sniff(csvfile.read(10*1024))
            csvfile.seek(0)

            # check with sniff if the CSV file has a header
            has_header = csv.Sniffer().has_header(csvfile.read(10*1024))
            csvfile.seek(0)

            reader = csv.reader(csvfile, dialect=dialect)
            if has_header:
                csv_header = next(reader)
                csv_column_amount = len(csv_header)

            new_csv_rows = []
            for row in reader:  # query GreyNoise
                csv_column_amount = len(row)
                data = query_ip(row[ip_column_idx], source_csv=True, single_ip=False)
                new_csv_rows.append(get_enriched_csv_row(row, data))
                print_ip_query(data, single_ip=False)

                if output_to_file:
                    response_data.append(data)

        # create the CSV header
        if not has_header:
            for i in range(0, csv_column_amount):
                csv_header.append('column_'+str(i))
            csv_header[ip_column_idx] = 'IP-address'
        for column_name in CSV_HEADER_ENRICHMENT:
            csv_header.append(column_name)

        # write the new CSV file
        dialect.quoting = csv.QUOTE_ALL
        dialect.escapechar = '"'
        greynoise_csv_file_path = os.path.dirname(csv_file_path)+'/greynoise_'+os.path.basename(csv_file_path)
        with open(greynoise_csv_file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, dialect=dialect)
            writer.writerow(csv_header)
            writer.writerows(new_csv_rows)

        return response_data
    else:
        print('[!] CSV file does not exist')


def write_json_output_file(data, filepath, query_type):
    with open(filepath, mode='w', encoding='utf-8') as json_file:
        if query_type == 'ip' and HIDE_UNKNOWN:
            data_without_unknown = []
            for ip_response in data:
                if ip_response['status'] != 'unknown':
                    data_without_unknown.append(ip_response)
            json.dump(data_without_unknown, json_file)
        else:
            json.dump(data, json_file)


def write_csv_output_file(data, filepath, query_type):
    if data:
        if query_type == 'ip':
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(CSV_HEADER_IP)

                for ip_response in data:
                    len_records = 0

                    if 'records' in ip_response:
                        len_records = len(ip_response['records'])

                    if len_records == 0 and not HIDE_UNKNOWN:
                        row = [ip_response['ip'], ip_response['status']]
                        row += [''] * (len(CSV_HEADER_IP) - 2)
                        writer.writerow(row)

                    if len_records > 0:
                        ip = ip_response['ip']
                        status = ip_response['status']

                        for r in ip_response['records']:
                            tag_id = r['name']
                            tag_name = tag_id
                            if tag_id in TAGS:
                                tag_name = TAGS[tag_id]

                            row = list([ip, status])
                            row.append(r['metadata']['rdns'])
                            row.append(r['metadata']['rdns_parent'])
                            row.append(r['metadata']['asn'])
                            row.append(r['metadata']['org'])
                            row.append(tag_id)
                            row.append(tag_name)
                            row.append(r['category'])
                            row.append(r['intention'])
                            row.append(r['confidence'])
                            row.append(r['metadata']['datacenter'])
                            row.append(r['metadata']['os'])
                            row.append(r['metadata']['link'])
                            row.append(r['metadata']['tor'])
                            row.append(get_datetime(r['first_seen'], full_date=True))
                            row.append(get_datetime(r['last_updated'], full_date=True))

                            writer.writerow(row)

        if query_type == 'tag':
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(CSV_HEADER_IP)

                status = data['status']
                for r in data['records']:

                    tag_id = r['name']
                    tag_name = tag_id
                    if tag_id in TAGS:
                        tag_name = TAGS[tag_id]

                    row = list([r['ip'], status])
                    row.append(r['metadata']['rdns'])
                    row.append(r['metadata']['rdns_parent'])
                    row.append(r['metadata']['asn'])
                    row.append(r['metadata']['org'])
                    row.append(tag_id)
                    row.append(tag_name)
                    row.append(r['category'])
                    row.append(r['intention'])
                    row.append(r['confidence'])
                    row.append(r['metadata']['datacenter'])
                    row.append(r['metadata']['os'])
                    row.append(r['metadata']['link'])
                    row.append(r['metadata']['tor'])
                    row.append(get_datetime(r['first_seen'], full_date=True))
                    row.append(get_datetime(r['last_updated'], full_date=True))

                    writer.writerow(row)

        if query_type == 'list':
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(CSV_HEADER_LIST)

                tags = sorted(data['tags'])

                for tag in tags:
                    tag_name = ''
                    if tag in TAGS:
                        tag_name = TAGS[tag]
                    writer.writerow([tag, tag_name])


def menu(menu_parser):
    global API_KEY
    global HIDE_UNKNOWN
    response_data = []
    query_type = None

    load_config()
    args = menu_parser.parse_args()

    if args.cache_timeout:
        global CACHE_TIMEOUT
        if not re.match('^[0-9]+$', args.cache_timeout):
            print(args.cache_timeout+' is not a valid integer')
            quit()
        else:
            CACHE_TIMEOUT = int(args.cache_timeout)

    if args.key:
        API_KEY = args.API_kEY

    if args.hide_unknown:
        HIDE_UNKNOWN = True

    if args.cache_expire:
        expire_cache()

    if args.output and args.format == 'txt':
        sys.stdout = open(args.output, 'w')

    if args.ip:
        query_type = 'ip'
        initialize_column_name()
        initialize_cache()

        # try catch for invalid IP CIDR ranges
        try:
            net4 = ipaddress.ip_network(args.ip)
        except ValueError as e:
            print(e)
            quit()

        for ip in net4:
            data = query_ip(str(ip), single_ip=True)

            if data and args.output and args.format != 'txt':
                response_data.append(data)

            if net4.num_addresses > 1:
                print_ip_query(data, single_ip=False)
            else:
                print_ip_query(data, single_ip=True)

        save_cache()

    if args.file:
        query_type = 'ip'
        initialize_column_name()
        initialize_cache()
        lines = read_file(args.file)

        for line in lines:
            line = line.lstrip().rstrip()
            if line != '':  # skip emtpy lines
                # try catch for invalid IP CIDR ranges
                try:
                    net4 = ipaddress.ip_network(line)
                except ValueError as e:
                    print(e)
                    quit()

            for ip in net4:
                data = query_ip(str(ip), single_ip=False)
                if data and args.output and args.format != 'txt':
                    response_data.append(data)
                print_ip_query(data, single_ip=False)

        save_cache()

    if args.list:
        query_type = 'list'
        response_data = query_tag_list()
        print_tag_list(response_data)

    if args.tag:
        query_type = 'tag'
        response_data = query_tag(args.tag.upper())
        print_tag_records(response_data)

    # enrich CSV file
    if args.csv:
        query_type = 'ip'
        initialize_column_name()
        initialize_cache()

        if not re.match('^[0-9]+$', args.csv[1]):
            print(args.csv[1]+' is not a valid integer')
            quit()
        else:
            response_data = process_csv_file(args.csv, args.output)

        save_cache()

    # write all responses to a file (json or csv)
    if len(response_data) > 0 and args.output:
        if args.format == 'json':
            write_json_output_file(response_data, args.output, query_type)

        if args.format == 'csv':
            write_csv_output_file(response_data, args.output, query_type)


if __name__ == "__main__":
    menu_parser = init_menu()
    menu(menu_parser)
