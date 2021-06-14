# Does an asset export and for each asset, collects the vulnerability information.
# A gzip file in the form of assets_xxxx.gz and a unzip file assets_xxxx are left
# around.
#
# The script has one optional parameter, the search ID.  If specified, it is assumed
# that you know the search ID from a previous search.

import os
import sys
import time
import requests
import json
import gzip
import shutil
import math

# Invoke the data_exports API to request an asset export.
def request_asset_exports(api_key, base_url):
    url = base_url + "/data_exports"
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key}

    filter_params = {
        'status' : ['active'],
        #'records_updated_since' : 'now-01d',
        'export_settings': {
            'format': 'jsonl',
            'model': 'asset'
        }
    }
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(filter_params))
    except Exception as exp:
        print("Assets Data Exports Error: {str(exp)}")
        exit(1)
    
    resp = response.json()
    search_id = str(resp['search_id'])
    asset_count = resp['record_count']
    print(f"Search ID: {id}")
    print(f"Asset count: {asset_count}")
    return (search_id, asset_count)

def get_export_status(api_key, base_url, search_id):
    check_status_url = base_url + "/data_exports/status?search_id=" + search_id
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key}

    try:
        response = requests.get(check_status_url, headers=headers)
    except Exception as exp:
        print("Get Export Status Error: {str(exp)}")
        exit(1)
    
    resp_json = response.json()
    return resp_json['message'] == "Export ready for download"

# Check to see if the export file is ready to download.
def check_export_status(api_key, base_url, search_id, asset_count):

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
        ready = get_export_status(api_key, base_url, search_id)
        secs += wait_interval_secs 

    print("")
    if secs >= wait_limit_secs:
        print(f"Waited for {wait_limit_secs} seconds.")
        print(f"Consider re-running with search ID")
        sys.exit(1)
 
# Obtain the exported asset data.
def retrieve_asset_data(api_key, base_url, id, asset_file_name):
    get_data_url = base_url + "/data_exports/?search_id=" + id
    headers = {'Accept': 'application/gzip; charset=utf-8',
               'X-Risk-Token': api_key}
    
    gz_asset_file_name = asset_file_name + ".gz"
    try:
        response = requests.get(get_data_url, headers=headers, stream=True)
    
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

# Obtain and write vulnerability information per asset ID into the specified file.
def get_vuln_info(api_key, vuln_url, asset_id, avfp, avlfp):
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key}

    vuln_url = "https://" + vuln_url

    retry_cnt = 0
    success = False
    while not success:
       try:
           response = requests.get(vuln_url, headers=headers)
           http_status_code = response.status_code
   
           # If too many requests, wait a second.  If is happens again, error out.
           if http_status_code == 429:
               time.sleep(1)
               response = requests.get(vuln_url, headers=headers)
               response.raise_for_status()
   
       except requests.Timeout as tme:
           retry_cnt += 1
           print(f"\nGet vuln info Timeout error: {str(tme)}.  Sleeping 60s ({retry_cnt})")
           if retry_cnt > 3:
               return 
           time.sleep(60)
   
       except Exception as exp:
           print(f"\nGet vuln info error: {str(exp)}")
           return
        
       success = True
    
    resp_json = response.json()
    
    vulns = resp_json['vulnerabilities']
    num_vulns = len(vulns)
    print(f"Vulnerabilities for asset ID {asset_id} ({num_vulns})", file=avlfp)
    for vuln in vulns:
        print(vuln, file=avfp)

    return num_vulns

if __name__ == "__main__":
    # See if an ID is passed in.
    id = 0
    if len(sys.argv) > 1:
        id = sys.argv[1]
    asset_count = 0
    
    print("Assets Data Exports")
    
    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    # If ID is not defined then request an asset export, else verify.
    if id == 0:
        (id, asset_count) = request_asset_exports(api_key, base_url)
        print(f"New search ID: {id}")
        check_export_status(api_key, base_url, id, asset_count)
    else:
        print(f"Using search ID: {id}")
        get_export_status(api_key, base_url, id)
    
    asset_file_name = "assets_" + id
    gz_asset_file_name = retrieve_asset_data(api_key, base_url, id, asset_file_name)
    
    # Gunzip the file into another file.
    print(f"Unzipping file {gz_asset_file_name} to {asset_file_name}")
    with gzip.open(gz_asset_file_name, 'rb') as f_in:
        with open(asset_file_name, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    asset_count = count_lines(asset_file_name) 
    time_left_secs = math.ceil(asset_count / 1.7)
    print(f"Estimated processing time for {asset_count} assets: {time_left_secs} seconds. ({time_left_secs/60:0.1f} minutes)")
    
    # Open files for vulnerabilities per asset, and vulnerabilites info based on search ID.
    avfp = open("asset_vuln_info_" + id, "w")
    avlfp = open("asset_vuln_log_" + id, "w")
    
    # Read the asset file looking for asset ID, and for each asset ID obtain the vuln information.
    asset_cntr = 0
    vuln_cntr = 0
    start_time = time.perf_counter()
    acc_start_time = start_time
    with open(asset_file_name) as asset_file:
        for json_line in asset_file:
            asset = json.loads(json_line)
            vuln_url = asset['urls']['vulnerabilities']
    
            vuln_cntr += get_vuln_info(api_key, vuln_url, str(asset['id']), avfp, avlfp)
            asset_cntr += 1
            if asset_cntr != 0 and asset_cntr % 5 == 0:
                time_lapse = time.perf_counter() - start_time
                if (time_lapse) < 1.0:
                    print(f"\nExceeded 5 API calls per second.")
                    time.sleep(1)
    
                if asset_cntr % 25 == 0:
                    time_left_secs = (asset_count - asset_cntr) / (time_lapse / 5)
                    print(f"Processed {asset_cntr} assets and {vuln_cntr} vulns. ({time_left_secs:0.1f}s  {time_left_secs/60:0.1f}m)   \r", end='')
    
                start_time = time.perf_counter()
    
    total_time_secs = time.perf_counter() - acc_start_time
    avfp.close()
    print(f"Processed {asset_cntr} assets and {vuln_cntr} vulns in {total_time_secs:0.1f}s  ({total_time_secs/60:0.1f}m)   ")
