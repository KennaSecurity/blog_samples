# Does an vulnerability export with vulnerability details and selected fields.
#
# A gzip file in the form of vulns_xxxx.gz and a unzip file vulns_xxxx are left
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
import json
import gzip
import shutil
from textwrap import dedent

# Print help.
def print_help():
    prog_name = sys.argv[0]
    
    print(dedent(f"""
        Obtains a vulnerability export with vulnerability details into a .gz file.
    
        There are 2 formats:
            {prog_name}
            {prog_name} <export_search_id>
        Where <export_search_id> is search ID from an vuln export.
        If <export_search_id> is not present, a new export is created and retrieved.
    
        There are one output file:
            vulns_<export_id>.jsonl
    """).lstrip())
    
    logging.info("Exited after helping.")
    sys.exit(1)

# Print and log information.
def print_info(msg):
    print(msg)
    logging.info(msg)

# Print and error information.
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

# Converts a line of JSON (JSONL) into a Python dictionary.
def convert_from_jsonl(vuln_line):
    try:
        json_vuln = json.loads(vuln_line.strip())
    except json.JSONDecodeError:
        print("The file's format is probably not JSONL, but XML or CSV")
        sys.exit(1)
    
    return json_vuln

# Invoke the data_exports API to request an vuln export.
def request_vuln_exports(base_url, headers, selected_fields):
    request_export_url = f"{base_url}/data_exports"

    filter_params = {
        'status' : ['open'],
        'export_settings': {
            'format': 'jsonl',
            'model': 'vulnerability',
            "fields": selected_fields
        }
    }
    
    response = requests.post(request_export_url, headers=headers, data=json.dumps(filter_params))
    if response.status_code != 200:
        process_http_error(f"Request Data Export API Error", response, request_export_url)
        sys.exit(1)
    
    resp = response.json()
    export_search_id = str(resp['search_id'])
    num_vulns = resp['record_count']
    print_info(f"New export search ID: {export_search_id} with {num_vulns} vulnerabilities.")
    return export_search_id

# Get the export status.  Return True when the correct phrase is returned.
def get_export_status(base_url, headers, export_search_id):
    check_status_url = f"{base_url}/data_exports/status?search_id={export_search_id}"

    # Check the export status.
    response = requests.get(check_status_url, headers=headers)
    if response.status_code == 206:
        return False
    if response.status_code != 200:
        process_http_error(f"Check Data Export Status API Error", response, check_status_url)
        sys.exit(1)
    
    resp_json = response.json()
    return True if resp_json['message'] == "Export ready for download" else False
    
# Check to see if the export file is ready to download.
def check_export_status(base_url, headers, export_search_id):

    # Loop to check status for 20 minutes.
    wait_minutes = 20
    interval_secs = 5
    wait_count = round(wait_minutes * (60 / interval_secs))
    cnt = 1
    ready = False

    # Check the export status until the export is ready or the time limit is met.
    while not ready and cnt < wait_count:
        print(f"Sleeping for {interval_secs} seconds.  ({cnt} out of {wait_count})\r", end='')
        time.sleep(interval_secs)
        cnt += 1

        ready = get_export_status(base_url, headers, export_search_id)

    print("")
    if cnt >= wait_count:
        print_info(f"Waited for {wait_minutes} minutes.")
        print_info(f"Consider re-running with search ID")
        sys.exit(1)
 
# Obtain the exported vuln data and gunzip it.
def retrieve_vuln_data(base_url, base_headers, search_id, vuln_file_name):
    jsonl_vuln_file_name = f"{vuln_file_name}.jsonl"
    
    # Check if the JSONL file already exists.  This is useful when developing 
    # new process code after the export.
    if os.path.exists(jsonl_vuln_file_name):
        print_info(f"{jsonl_vuln_file_name} already exists, so we're using it.")
        return jsonl_vuln_file_name

    get_data_url = f"{base_url}/data_exports/?search_id={search_id}"
    headers = base_headers.copy()
    headers['Accept'] = "application/gzip; charset=utf-8"
    
    gz_vuln_file_name = vuln_file_name + ".gz"

    # Retrieve the gzip file by streaing.
    response = requests.get(get_data_url, headers=headers, stream=True)
    if response.status_code != 200:
        process_http_error(f"Retrieve Data Export API Error", response, get_data_url)
        sys.exit(1)

    try:
        with open(gz_vuln_file_name, 'wb') as file_gz:
            for block in response.iter_content(8192):
                file_gz.write(block)
    
    except Exception as exp:
        print_error(f"Retrieve vuln data Error: {exp.__str__()}")
        sys.exit(1)

    # Gunzip the file into the JSONL file.
    print_info(f"Gunzipping file {gz_vuln_file_name} to {jsonl_vuln_file_name}")
    with gzip.open(gz_vuln_file_name, 'rb') as f_in:
        with open(jsonl_vuln_file_name, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    print_info(f"File {gz_vuln_file_name} gunzipped to {jsonl_vuln_file_name}")
    f_out.close()
    f_in.close()
    return jsonl_vuln_file_name

# Count the number of lines in the unzip asset file.
# From: https://stackoverflow.com/questions/845058/how-to-get-line-count-of-a-large-file-cheaply-in-python
def count_lines(vuln_file_name):
    print_info(f"Counting lines in {vuln_file_name}")

    f = open(vuln_file_name, 'rb')
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

def convert_to_json(vuln_line):
    try:
        vuln = json.loads(vuln_line.strip())
    except json.JSONDecodeError:
        print_error("The file's format is probably not JSONL, but XML or CSV")
        sys.exit(1)
    
    return vuln

if __name__ == "__main__":
    logging_file_name = "get_vuln_details.log"
    logging_format = "%(asctime)s %(levelname)s %(message)s"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO, format=logging_format)
    print_info("Vulnerabiity Exports with Details")

    # Process command line arguments.
    export_id = 0
    try:
        if len(sys.argv) == 2:
            if sys.argv[1] == "-h":
                print_help()
            else:
                export_id = int(sys.argv[1])
    except ValueError:
        print("Bad string to integer conversion for search ID")
        print_help()
    
    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print_error("Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key,
               'User-Agent': 'vuln_exports/1.0.0 (Kenna Security)'}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com"
    
    # Seleted fields to be returned.
    selected_fields = [
        "cve_description", 
        "cve_id",
        "description",
        "details", 
        "id",
        "scanner_score",
        "solution",
        "risk_meter_score", 
    ]

    # If an export ID is not defined then do an vuln export.
    if export_id == 0:
        export_id = request_vuln_exports(base_url, headers, selected_fields)
    else:
        print_info(f"Using search ID: {export_id}")
    check_export_status(base_url, headers, export_id)
    
    # Create the file name based on the search ID.
    vuln_file_name = f"vulns_{export_id}"
    jsonl_vuln_file_name = retrieve_vuln_data(base_url, headers, export_id, vuln_file_name)
    
    # Count and report.
    num_vulns = count_lines(jsonl_vuln_file_name) 
    if num_vulns == 1:
        print_error(f"The format of file {jsonl_vuln_file_name} is probably JSON, not JSONL")
        sys.exit(1)

    print_info(f"File: {jsonl_vuln_file_name} with {num_vulns} vulns.")
