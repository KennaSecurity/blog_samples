from json.tool import main
import os
import sys
import csv
import time
import json
import logging
import requests
import gzip
import shutil
import math

# Class to store asset tag information.
# (This is class is small, but will be enlarged in part 2.)
class Asset_Tag_Info:
    def __init__(self):
        self.count = 1

    def incr(self):
        self.count += 1

    def get_count(self):
        return self.count

# Print help.
def print_help():
    prog_name = sys.argv[0]
    print("Gets unique asset tags and puts them in a CSV file.")
    print("The <id> is search ID from an asset export.")
    print("If <id> is not present, a new export is created and retrieved.")
    print("")

    print("There are 2 formats:")
    print(f"    {prog_name}")
    print(f"    {prog_name} <id>")
    print("")
    
    print("To obtain this output:")
    print(f"    {prog_name} -h")
    print("")

    sys.exit(1)

# Print and log information.
def print_info(msg):
    print(msg)
    logging.info(msg)

# Process an HTTP error by printing and log.error
def process_http_error(msg, response, url):
    print(f"{msg} HTTP Error: {response.status_code} with {url}")
    if response.text is None:
        logging.error(f"{msg}, {url} status_code: {response.status_code}")
    else:
        logging.error(f"{msg}, {url} status_code: {response.status_code} info: {response.text}")

# Invoke the data_exports API to request an asset export.
def request_asset_exports(base_url, headers):
    request_export_url = f"{base_url}data_exports"

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
    print_info(f"New search ID: {search_id} with {num_assets} assets")
    return (search_id, num_assets)

def get_export_status(base_url, headers, search_id):
    check_status_url = f"{base_url}data_exports/status?search_id={search_id}"

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

    # Check if the export is ready already.
    ready = get_export_status(base_url, headers, search_id)
    if ready:
        return
    
    # Estimate export time for if we're waiting.
    # Calculate wait interval between checking if the export file is ready.
    wait_interval_secs = 5 if num_assets < 2718 else 10
    wait_limit_secs = math.ceil(num_assets / 16)

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
        print_info(f"Waited for {wait_limit_secs} seconds.")
        print(f"Consider re-running with search ID")
        sys.exit(1)
 
# Obtain the exported asset data and ungzip it.
def retrieve_asset_data(base_url, base_headers, id, asset_file_name):
    jsonl_asset_file_name = f"{asset_file_name}.jsonl"

    if os.path.exists(jsonl_asset_file_name):
        print_info(f"{jsonl_asset_file_name} already exists, so we're using it.")
        return jsonl_asset_file_name

    gz_asset_file_name = f"{asset_file_name}.gz"

    get_data_url = f"{base_url}data_exports/?search_id={id}"
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

# Process a string of asset tags.  Each asset tag is checked if it exists in the 
# the asset tag dictionar.
def process_tags(asset_id, tags_to_process, asset_tags):
    for tag in tags_to_process:
        if tag in asset_tags:
            asset_tags[tag].incr()
            logging.debug(f"Existing asset tag: {tag} ({asset_id})")
        else:
            tag_info = Asset_Tag_Info()
            asset_tags[tag] = tag_info
            logging.info(f"New asset tag: {tag} ({asset_id})") 

# Read the JSONL file and process it line by line.
def process_jsonl_file(jsonl_asset_file_name, asset_tags):
    print_interval = 50
    asset_count = 0

    with open(jsonl_asset_file_name, 'r') as jsonl_f:
        for line_num, asset_line in enumerate(jsonl_f):
            asset = json.loads(asset_line.strip())
            #print(f"{asset}")
            if "tags" in asset:
                #print(f"{asset['id']}: {asset['tags']}")
                process_tags(asset['id'], asset['tags'], asset_tags)
            asset_count += 1
            if asset_count % print_interval == 0:
                logging.info(f"{asset_count} processed")

    print("")
    return asset_count

def write_csv_file(asset_tags):
    # Open up the CSV file and write the header row.
    csv_file_name = "uniq_asset_tags.csv"
    uniq_asset_tags_fp = open(csv_file_name, 'w', newline='')
    uniq_tag_writer = csv.writer(uniq_asset_tags_fp)
    uniq_tag_writer.writerow(["Asset Tag Name", "Asset Tag Count"])

    # Write the CSV file.
    for asset_tag in asset_tags:
        asset_tag_info = asset_tags[asset_tag]
        uniq_tag_writer.writerow([asset_tag, asset_tag_info.get_count()])

if __name__ == "__main__":
# See if an ID is passed in.
    logging_file_name = "uniq_asset_tags.log"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO)
    print_info(f"Get Unique Asset Tags")

    # Process command line arguments.
    id = 0
    try:
        if len(sys.argv) == 2:
            if sys.argv[1] == "-h":
                print_help()
            else:
                id = int(sys.argv[1])
    except ValueError:
        print("Bad string to integer conversion")
        print_help()

    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'unique_asset_tags/1.0.0 (Kenna Security)'}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    # If ID is not defined then request an asset export, else verify.
    if id == 0:
        (id, num_assets) = request_asset_exports(base_url, headers)
        check_export_status(base_url, headers, id, num_assets)
    else:
        print_info(f"Using search ID: {id}")
        check_export_status(base_url, headers, id, 50000)
    
    asset_file_name = f"assets_{id}"
    jsonl_asset_file_name = retrieve_asset_data(base_url, headers, id, asset_file_name)
    
    # Count and report.
    num_assets = count_lines(jsonl_asset_file_name) 
    print(f"File: {jsonl_asset_file_name} with {num_assets} assets.")
    
    asset_tags = {} 
    asset_count = process_jsonl_file(jsonl_asset_file_name, asset_tags)
    logging.info(f"Total {asset_count} assets processed")

    num_uniq_asset_tags = len(asset_tags)
    print_info(f"{num_uniq_asset_tags} unique asset tags discovered.")

    write_csv_file(asset_tags)