# Does an asset export and for each asset, collects the vulnerability information.
# A gzip file in the form of assets_xxxx.gz and a unzip file assets_xxxx are left
# around.
#
# The script has one optional parameter, the search ID.  If specified, it is assumed
# that you know the search ID from a previous search.

import os
import sys
import time
import json
import logging
import requests
import gzip
import shutil
import math

# Print and log information.
def process_info(msg):
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
    asset_count = resp['record_count']
    print(f"Search ID: {id}")
    print(f"Asset count: {asset_count}")
    return (search_id, asset_count)

def get_export_status(base_url, headers, search_id):
    check_status_url = base_url + "/data_exports/status?search_id=" + search_id

    response = requests.get(check_status_url, headers=headers)
    if response.status_code != 200:
        process_http_error(f"Get Export Status API Error", response, check_status_url)
        sys.exit(1)
    
    resp_json = response.json()
    return resp_json['message'] == "Export ready for download"

# Check to see if the export file is ready to download.
def check_export_status(base_url, headers, search_id, asset_count):

    # Estimate export time for if we're waiting.
    # Calculate wait interval between checking if the export file is ready.
    wait_interval_secs = 5 if asset_count < 1000 else 10
    wait_limit_secs = math.ceil(asset_count / 16)
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
        print(f"Consider re-running with search ID")
        sys.exit(1)
 
# Obtain the exported asset data.
def retrieve_asset_data(base_url, base_headers, id, asset_file_name):
    get_data_url = base_url + "/data_exports/?search_id=" + id
    headers = base_headers.copy()
    headers['Accept'] = "application/gzip; charset=utf-8"
    
    gz_asset_file_name = asset_file_name + ".gz"

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
        sys.exit(1)

    return gz_asset_file_name

# Count the number of lines in the unzip asset file.
# From: https://stackoverflow.com/questions/845058/how-to-get-line-count-of-a-large-file-cheaply-in-python
def count_lines(asset_file_name):
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

if __name__ == "__main__":
# See if an ID is passed in.
    logging_file_name = "export_assets.log"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO)
    process_info(f"Assets Data Export")

    id = 0
    if len(sys.argv) > 1:
        id = sys.argv[1]

    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'export_asset/1.0.0 (Kenna Security)'}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    asset_count = 0
    
    # If ID is not defined then request an asset export, else verify.
    if id == 0:
        (id, asset_count) = request_asset_exports(base_url, headers)
        process_info(f"New search ID: {id}")
        check_export_status(base_url, headers, id, asset_count)
    else:
        process_info(f"Using search ID: {id}")
        check_export_status(base_url, headers, id, 50000)
    
    asset_file_name = "assets_" + id
    gz_asset_file_name = retrieve_asset_data(base_url, headers, id, asset_file_name)
    
    # Gunzip the file into another file.
    print(f"Unzipping file {gz_asset_file_name} to {asset_file_name}")
    with gzip.open(gz_asset_file_name, 'rb') as f_in:
        with open(asset_file_name, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    # Count and report.
    asset_count = count_lines(asset_file_name) 
    print(f"File: {asset_file_name} with {asset_count} assets.")
    
