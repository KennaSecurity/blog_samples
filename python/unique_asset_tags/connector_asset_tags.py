from json.tool import main
import os
import sys
import time
import json
import argparse
import logging
import requests
import gzip
import shutil
import math

# Class to store connector information.
# Inherits from dictionary class for JSON decoding. See
# https://pynative.com/make-python-class-json-serializable/ for details.
class Connector_Info(dict):
    connectors_by_id = {}

    def __init__(self, connector_id):
        connector_name = Connector_Info.connectors_by_id[connector_id]
        dict.__init__(self, conn_id = connector_id, conn_name = connector_name)

    def conn_id(self):
        return self['conn_id']

    def conn_name(self):
        return self['conn_name']

# Class to store tag information.
# Inherits from dictionary class for JSON decoding. See
# https://pynative.com/make-python-class-json-serializable/ for details.
class Tag_Info(dict):
    def __init__(self, name):
        dict.__init__(self, name = name, connectors = [])

    def add_connector(self, connector_info:Connector_Info):
        self['connectors'].append(connector_info)
    
    def tag_name(self):
        return self['name']

    def connectors(self):
        return self['connectors']

# Class to store the asset information
# Inherits from dictionary class for JSON decoding. See
# https://pynative.com/make-python-class-json-serializable/ for details.
class Asset_Info(dict):
    def __init__(self, asset):
        id = asset['id'] 
        primary_locator = asset['primary_locator']
        locator = asset[primary_locator]
        dict.__init__(self, asset_id = id, asset_locator = locator, tag_infos = [])

    def add_tag_info(self, tag_info):
        self['tag_infos'].append(tag_info)
        return
    
    def asset_id(self):
        return self['asset_id']

    def asset_locator(self):
        return self['asset_locator']

    def tags(self):
        return self['tag_infos']

def get_command_line_options():
    # Create the argument parser with a description.
    arg_parser = argparse.ArgumentParser(description="Get connector tags for assets.")

    # Add the arguments.
    arg_parser.add_argument("-i", "--input_file",
                            dest='input_file_name',
                            required=False,
                            default="scanner_tags.txt",
                            help="Scanner tags input file name.  Default is 'scanner_tags.txt'")

    arg_parser.add_argument("-o", "--output_file",
                            dest='output_file_name',
                            required=False,
                            default="connector_asset_tags.jsonl",
                            help="Asset tag connector JSONL output file name.  Default is 'connector_asset_tags.jsonl'")

    arg_parser.add_argument("-s", "--search_id",
                            dest='search_id',
                            required=False,
                            default=0,
                            help="Previous search ID.")

    # Parse and return results.
    args = arg_parser.parse_args()
    return args

# Print and log information.
def print_info(msg):
    print(msg)
    logging.info(msg)

# Print and log error information.
def print_error(msg):
    print(msg)
    logging.error(msg)

# Process an HTTP error by printing and log.error
def process_http_error(msg, response, url):
    print(f"{msg} HTTP Error: {response.status_code} with {url}")
    if response.text is None:
        logging.error(f"{msg}, {url} status_code: {response.status_code}")
    else:
        logging.error(f"{msg}, {url} status_code: {response.status_code} info: {response.text}")

# Get the list of connectors hashed by ID.
def get_connectors_by_id(base_url, headers):
    connectors_by_id = {}

    connector_request_url = f"{base_url}/connectors"

    response = requests.get(connector_request_url, headers=headers)
    if response.status_code != 200:
        process_http_error(f"List Connectors API Error", response, connector_request_url)
        sys.exit(1)

    resp = response.json()
    connectors = resp['connectors']

    for connector in connectors:
        connectors_by_id[connector['id']] = connector['name']

    return connectors_by_id

# Retrieve the scanner tags and put then in a dictionary key by scanner tag.
def get_scanner_tags(input_tags_file_name):
    scanner_tags = {}
    num_tags = 0

    try:
        scanner_tags_f = open(input_tags_file_name, "r")
    except FileNotFoundError:
        print_error(f"File {input_tags_file_name} not found.")
        sys.exit(1)

    for scanner_tag in scanner_tags_f:
        scan_tag_name = scanner_tag.strip()
        scanner_tags[scan_tag_name] = 0
        num_tags += 1

    print_info(f"Number of scanner tags: {num_tags}")
    return scanner_tags

# Invoke the data_exports API to request an asset export.
def request_asset_exports(base_url, headers):
    request_export_url = base_url + "/data_exports"

    filter_params = {
        'status' : ['active'],
        'export_settings': {
            'format': 'jsonl',
            'model': 'asset'
        }
    }
    
    response = requests.post(request_export_url, headers=headers, data=json.dumps(filter_params))
    if response.status_code != 200:
        process_http_error(f"Request Data Export API Error", response, request_export_url)
        sys.exit(1)

    resp = response.json()
    search_id = str(resp['search_id'])
    num_assets = resp['record_count']
    return (search_id, num_assets)

def get_export_status(base_url, headers, search_id):
    check_status_url = f"{base_url}/data_exports/status?search_id={search_id}"

    response = requests.get(check_status_url, headers=headers)
    if response.status_code == 206:
        return False
    if response.status_code != 200:
        process_http_error(f"Get Export Status API Error", response, check_status_url)
        sys.exit(1)
    
    resp_json = response.json()
    return resp_json['message'] == "Export ready for download"

# Check to see if the export file is ready to download.
def check_export_status(base_url, headers, search_id, num_assets):
    export_overhead_secs = 30

    # Estimate export time for if we're waiting.
    # Calculate wait interval between checking if the export file is ready.
    wait_interval_secs = 5 if num_assets < 1000 else 10
    wait_limit_secs = math.ceil(num_assets / 10) + export_overhead_secs
    wait_limit_minutes = math.ceil(wait_limit_secs/60)
    if wait_limit_minutes > 2:
        print(f"The export will take approximately {wait_limit_minutes} minutes.")
    else:
        print(f"The export will take approximately {wait_limit_secs} seconds.")

    # Loop to check status for wait_limit_secs seconds.
    secs = 0
    ready = False
    while not ready and secs < wait_limit_secs:
        print(f"Sleeping for {wait_interval_secs} seconds. ({secs})\r", end='')
        time.sleep(wait_interval_secs)
        ready = get_export_status(base_url, headers, search_id)
        secs += wait_interval_secs 

    print("")
    if secs >= wait_limit_secs:
        print(f"Waited for {wait_limit_secs} seconds.")
        print(f"Consider re-running with search ID {search_id}")
        sys.exit(1)
 
def json_file_exists(jsonl_asset_file_name):
    if os.path.exists(jsonl_asset_file_name):
        print_info(f"{jsonl_asset_file_name} already exists, so we're using it.")
        return True
    
    return False

# Obtain the exported asset data and ungzip it.
def retrieve_asset_data(base_url, base_headers, id, asset_file_name, jsonl_asset_file_name):
    gz_asset_file_name = f"{asset_file_name}.gz"

    get_data_url = base_url + "/data_exports/?search_id=" + id
    headers = base_headers.copy()
    headers['Accept'] = "application/gzip; charset=utf-8"
    
    response = requests.get(get_data_url, headers=headers, stream=True)
    if response.status_code != 200:
        process_http_error(f"Retrieve Data Export API Error", response, get_data_url)
        sys.exit(1)
    
    try:
        with open(gz_asset_file_name, 'wb') as file_gz:
            for block in response.iter_content(8192):
                file_gz.write(block)
    
    except Exception as exp:
        print(f"Retrieve asset data error: {str(exp)}")
        logging.error(f"Retrieve asset data error: {str(exp)}")
        sys.exit(1)

    # Gunzip the file into another file.
    print_info(f"Unzipping file {gz_asset_file_name} to {jsonl_asset_file_name}")
    with gzip.open(gz_asset_file_name, 'rb') as f_in:
        with open(jsonl_asset_file_name, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    print_info(f"File {gz_asset_file_name} unzipped to {jsonl_asset_file_name}")
    return jsonl_asset_file_name

# Count the number of lines in the unzip asset file.
# From: https://stackoverflow.com/questions/845058/how-to-get-line-count-of-a-large-file-cheaply-in-python
def count_lines(asset_file_name):
    print_info(f"Counting lines in {asset_file_name}")

    f = open(asset_file_name, 'rb')
    lines = 0
    buf_size = 1024 * 1024
    read_f = f.raw.read

    buf = read_f(buf_size)
    while buf:
        lines += buf.count(b'\n')
        buf = read_f(buf_size)
    
    f.close()

    # Add one to the number of lines because the end of files does not have '\n'.
    return lines + 1

# Returns the asset locator; for example IP address, or host name.
def get_asset_locator(asset):
    primary_locator = asset['primary_locator']
    asset_locator = asset[primary_locator]
    return asset_locator

def tags_in_list(tags_to_process, scanner_tags):
    for tag in tags_to_process:
        if tag in scanner_tags:
            return True
        
    return False

# Get the connector information and associate them with the tag
# if in the list of scanner tags.
def get_connector_info(tag_info:Tag_Info, tag_connectors):

    for connector in tag_connectors:
        conn_id = connector['connector_id']
        conn_info = Connector_Info(conn_id)
        tag_info.add_connector(conn_info)
        logging.info(f"Added connector {conn_info.conn_name()} to tag {tag_info.tag_name()}")
    
    return 

# Obtains the asset tags and return asset connector tags.
def get_asset_tags(base_url, headers, asset_id):
    
    tag_request_url = f"{base_url}/assets/{asset_id}/tags"

    response = requests.get(tag_request_url, headers=headers)
    if response.status_code != 200:
        process_http_error(f"List asset tags API Error", response, tag_request_url)
        sys.exit(1)

    resp = response.json()
    tag_info = resp['tag_info']

    return tag_info

# Get the connector tags for an asset.
def get_asset_connector_tags(asset_info:Asset_Info, asset_tags, scanner_tags):
    num_connector_tags = 0

    for tag in asset_tags:
        tag_sources = tag['tag_sources']

        if "connectors" in tag_sources and len(tag_sources['connectors']) > 0:
            tag_name = tag['tag_name']
            if not tag_name in scanner_tags:
                continue

            tag_info = Tag_Info(tag_name)
            num_connector_tags += 1
            get_connector_info(tag_info, tag_sources['connectors']) 
            asset_info.add_tag_info(tag_info)
            logging.info(f"Added tag {tag_info.tag_name()} to asset {asset_info.asset_locator()}")

    return num_connector_tags

# Write a line of JSON.
def write_jsonl(jsonl_f, asset_info:Asset_Info):
    out_line = json.dumps(asset_info)
    jsonl_f.write(f"{out_line}\n")

if __name__ == "__main__":
# See if an ID is passed in.
    logging_file_name = "connector_asset_tags.log"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO)
    print_info(f"Connector Asset Tags")

    # Get command line arguments.
    args = get_command_line_options()
    input_tags_file_name = args.input_file_name
    output_asset_tags_file_name = args.output_file_name
    search_id = args.search_id

    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'connector_asset_tags/1.0.0 (Kenna Security)'}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    # Default the number of assets.
    num_assets = 50000

    # If ID is not defined then request an asset export.
    if search_id == 0:
        (search_id, num_assets) = request_asset_exports(base_url, headers)
        print_info(f"New search ID {search_id} with {num_assets} assets.")

    # Get scanner tag list from a file.
    scanner_tags = get_scanner_tags(input_tags_file_name)
        
    # Get a list of connectors mapping connector ID to name.
    Connector_Info.connectors_by_id = get_connectors_by_id(base_url, headers)

    print_info(f"Checking if search ID: {search_id} is ready")

    asset_file_name = f"assets_{search_id}"
    jsonl_asset_file_name = f"{asset_file_name}.jsonl"

    if not json_file_exists(jsonl_asset_file_name):
        check_export_status(base_url, headers, search_id, num_assets)
        retrieve_asset_data(base_url, headers, search_id, asset_file_name, jsonl_asset_file_name)
    
    # Count and report.
    num_assets = count_lines(jsonl_asset_file_name) 
    print_info(f"File: {jsonl_asset_file_name} with {num_assets} assets.")
    
    try:
        out_file_f = open(output_asset_tags_file_name, "w")
    except FileNotFoundError:
        print_error(f"File {output_asset_tags_file_name} not found.")
        sys.exit(1)

    print_interval = 50
    asset_tags = {} 
    asset_count = 0
    asset_with_tags_count = 0
    connector_tag_count = 0

    with open(jsonl_asset_file_name, 'r') as jsonl_f:
        for line_num, asset_line in enumerate(jsonl_f):
            asset_count += 1
            if asset_count % print_interval == 0:
                logging.info(f"{asset_count} processed")

            # One JSON line is an asset.
            asset = json.loads(asset_line.strip())

            # Check if the asset has tags and if the tags are in the list.
            if not("tags" in asset and len(asset['tags']) > 0):
                continue
            if not tags_in_list(asset['tags'], scanner_tags):
                continue

            asset_id = asset['id']

            # Get a list of tags for the asset.
            asset_tags = get_asset_tags(base_url, headers, asset_id)
            if len(asset_tags) == 0:
                print_error(f"The number of asset tags should be greater that 0.")
                sys.exit(1)

            # Now that we know we have an asset with connector tags,
            # obtain an asset information object.
            asset_info = Asset_Info(asset)
            # logging.info(f"Processing asset {asset_info.asset_locator} connector tags.")

            # Determine if the asset has connector tags.
            num_connector_tags = get_asset_connector_tags(asset_info, asset_tags, scanner_tags)
            if num_connector_tags == 0:
                # logging.info(f"No connector tags for asset {asset_info.asset_locator}")
                continue
            
            connector_tag_count += num_connector_tags
            asset_with_tags_count += 1

            write_jsonl(out_file_f, asset_info)
                
    out_file_f.close()
    print_info(f"Total {asset_count} assets processed with {asset_with_tags_count} assets with tags with {connector_tag_count} connector tags.")
