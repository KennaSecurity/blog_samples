# Lists the top ten CVEs by count
#
# Does an vulnerability export and for each vulnerability, counts the 
# occurance of the CVE ID fitting the "CVE-XXXX-YYYY" pattern.  Informational
# CVE IDs are not counted..
#
# A gzip file in the form of vulns_xxxx.gz and a unzip file vulns_xxxx are left
# around.
#
# The script has one optional parameter, the search ID.  If specified, it is assumed
# that you know the search ID from a previous search.

import os
import sys
import csv
import time
import json
import logging
import requests
import json
import gzip
import shutil

VERSION = "1.0.0"

# Print help.
def print_help():
    prog_name = sys.argv[0]
    print("")
    print("Counts unique CVE IDs in the form CVE-XXXX-YYYY, displays the top ten,")
    print("and puts them all in a CSV file.")
    print("A vuln export is processed to obtain CVE counts.")
    print("")

    print("There are 2 formats:")
    print(f"    {prog_name}")
    print(f"    {prog_name} <search_id>")
    print("Where <search_id> is search ID from an vuln export.")
    print("If <search_id> is not present, a new export is created and retrieved.")
    print("")

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

# Invoke the data_exports API to request an vuln export.
def request_vuln_exports(base_url, headers):
    request_export_url = f"{base_url}/data_exports"

    filter_params = {
        'status' : ['open'],
        'export_settings': {
            'format': 'jsonl',
            'model': 'vulnerability'
        }
    }
    
    response = requests.post(request_export_url, headers=headers, data=json.dumps(filter_params))
    if response.status_code != 200:
        process_http_error(f"Request Data Export API Error", response, request_export_url)
        sys.exit(1)
    
    resp = response.json()
    search_id = str(resp['search_id'])
    num_vulns = resp['record_count']
    print_info(f"New search ID: {search_id} with {num_vulns} vulnerabilities.")
    return search_id

# Get the export status.  Return True when the correct phrase is returned.
def get_export_status(base_url, headers, search_id):
    check_status_url = f"{base_url}/data_exports/status?search_id={search_id}"

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
def check_export_status(base_url, headers, search_id):

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

        ready = get_export_status(base_url, headers, search_id)

    print("")
    if cnt >= wait_count:
        print_info(f"Waited for {wait_minutes} minutes.")
        print_info(f"Consider re-running with search ID")
        sys.exit(1)
 
# Obtain the exported vuln data and gunzip it.
def retrieve_vuln_data(base_url, base_headers, id, vuln_file_name):
    jsonl_vuln_file_name = f"{vuln_file_name}.jsonl"
    
    # Check if the JSONL file already exists.  This is useful when developing 
    # new process code after the export.
    if os.path.exists(jsonl_vuln_file_name):
        print_info(f"{jsonl_vuln_file_name} already exists, so we're using it.")
        return jsonl_vuln_file_name

    get_data_url = f"{base_url}/data_exports/?search_id={id}"
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

def convert_from_jsonl(vuln_line):
    try:
        vuln = json.loads(vuln_line.strip())
    except json.JSONDecodeError:
        print_error("The file's format is probably not JSONL, but XML or CSV")
        sys.exit(1)
    
    return vuln

# Process a CVE ID found in a vulnerability.
def process_cve_id_in_vuln(vuln, cve_counts):
    if vuln['cve_id'] == "":
        return

    # Get the CVE ID, and proceed if the CVE ID starts with "CVE-".
    cve_id = vuln['cve_id']
    cve_str = cve_id[0:4].upper()
    if cve_str != "CVE-":
        return

    if cve_id in cve_counts:
        cve_counts[cve_id] += 1
    else:
        cve_counts[cve_id] = 1

# Process vulnerabilities in the JSONL format.
def process_vuln_export(jsonl_vuln_file_name, cve_counts):
    print_info(f"Opening {jsonl_vuln_file_name} for processing.")
    logging_interval = 1000

    # Open the JSONL file and read it line by line, checking each vulnerability line for custom fields.
    with open(jsonl_vuln_file_name, 'r') as jsonl_f:
        for line_num, vuln_line in enumerate(jsonl_f):
            vuln = convert_from_jsonl(vuln_line)
            if "cve_id" in vuln:
                process_cve_id_in_vuln(vuln, cve_counts)
                #logging.info(f"Found cve_id {vuln['cve_id']} in vuln {line_num}")
        
            if (line_num + 1) % logging_interval == 0:
                print(".", end='', flush='True')

    print("")
    return (line_num + 1)

# Write the information out to a CSV file.
def write_csv_file(sorted_cve_counts):
    csv_filename = "uniq_cve_ids.csv"

    print_info(f"Dumping to CSV file: {csv_filename}")

    with open(csv_filename, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file, delimiter=',')
        csv_writer.writerow(["CVE", "CVE Count"])
        
        for cve, cve_count in sorted_cve_counts.items():
            csv_writer.writerow([cve, cve_count])

    print_info(f"{csv_filename} is now available.")

if __name__ == "__main__":
    logging_file_name = "custom_fields.log"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO)
    print_info(f"Count Unique CVE IDs v{VERSION}")

    # Process command line arguments.
    id = 0
    try:
        if len(sys.argv) == 2:
            if sys.argv[1] == "-h" or sys.argv[1] == "--help":
                print_help()
            else:
                id = int(sys.argv[1])
    except ValueError:
        print("Bad string to integer conversion for search ID")
        print_help()
    
    # This is variable here in case you want to make it a command line argument.
    num_requested_values = 10

    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print_error("Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    user_agent = f"count_unique_cves/{VERSION} (Kenna Security)"
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key,
               'User-Agent': user_agent}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com"
    
    # If ID is not defined then do an vuln export.
    if id == 0:
        id = request_vuln_exports(base_url, headers)
    else:
        print_info(f"Using search ID: {id}")
    check_export_status(base_url, headers, id)
    
    # Create the file name based on the search ID.
    vuln_file_name = f"vulns_{id}"
    jsonl_vuln_file_name = retrieve_vuln_data(base_url, headers, id, vuln_file_name)
    
    # Count and report.
    num_vulns = count_lines(jsonl_vuln_file_name) 
    if num_vulns == 1:
        print_error(f"The format of file {jsonl_vuln_file_name} is probably JSON, not JSONL")
        sys.exit(1)
    print_info(f"File: {jsonl_vuln_file_name} with {num_vulns} vulns.")
    

    # A dictionary indexed by CVE containing the CVE count.
    cve_counts = {}
    vulns_processed = process_vuln_export(jsonl_vuln_file_name, cve_counts)
    print_info(f"Total {vulns_processed} vulns processed.")
    
    num_cve_ids = len(cve_counts)
    print_info(f"{num_cve_ids} processed.")

    # Let's sort the CVEs by count.
    print_info(f"Sorting {num_cve_ids} CVEs")
    sorted_cve_counts = dict(sorted(cve_counts.items(), key=lambda items:items[1], reverse=True))
    
    # Display the top requested values.
    print("")
    print(f"Top {num_requested_values} CVE counts")
    count = 0
    for cve, cve_count in sorted_cve_counts.items():
        print(f"{cve}: {cve_count}")
        count +=1
        if count >= num_requested_values:
            break

    write_csv_file(sorted_cve_counts)
