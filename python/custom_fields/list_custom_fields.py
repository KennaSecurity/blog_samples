# Does an vuln export and for each vuln, collects the vulnerability information.
# A gzip file in the form of vulns_xxxx.gz and a unzip file vulns_xxxx are left
# around.
#
# The script has one optional parameter, the search ID.  If specified, it is assumed
# that you know the search ID from a previous search.

from email.mime import base
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

# Class to store a custom field.
class Custom_Field:
    def __init__(self, custom_field_info):
        self.custom_field_name = custom_field_info["name"]
        self.custom_field_id = custom_field_info["custom_field_definition_id"]
        self.custom_field_values = []
        self.custom_field_count = 0
        self.append_new_value(custom_field_info["value"])

    # Append a custom field value to the list of values.
    def append_new_value(self, custom_field_value):
        if custom_field_value is None:
            return

        self.custom_field_count += 1

        # If the value is not in the list of values, add it.
        if not custom_field_value in self.custom_field_values:
            self.custom_field_values.append(custom_field_value)
    
    # Obtain the list of custom field values.
    def get_values(self):
        out_str = ""
        for a_value in self.custom_field_values:
            out_str += f"{a_value}, "

        # Remove trailing comma and blank.
        out_str = out_str[:-1]
        out_str = out_str[:-1]
        return out_str

    # Obtain the number of values.
    def get_num_values(self):
        return len(self.custom_field_values)

# Print help.
def print_help():
    prog_name = sys.argv[0]
    print("")
    print("Gets unique custom fields, count, and values, and puts them in a CSV file.")
    print("A vuln export is processed to obtain custom field data.")
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
    request_export_url = base_url + "/data_exports"

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

# Check to see if the export file is ready to download.
def check_export_status(base_url, headers, search_id):
    check_status_url = f"{base_url}/data_exports/status?search_id={search_id}"

    # Loop to check status for 20 minutes.
    wait_minutes = 20
    interval_secs = 5
    wait_count = wait_minutes * (60 / interval_secs)
    cnt = 0
    ready = False

    # Check the export status until the export is ready or the time limit is met.
    while not ready and cnt <= wait_count:
        try:
            response = requests.get(check_status_url, headers=headers)
        except Exception as exp:
            print_error(f"Check Status Error: {exp.__str__()}")
            exit(1)
    
        resp_json = response.json()
        if resp_json['message'] == "Export ready for download":
            ready = True
        else:
            print(f"Sleeping for {interval_secs} seconds.  ({cnt} out of {wait_count})\r", end='')
            time.sleep(interval_secs)
            cnt += 1

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

def convert_to_json(vuln_line):
    try:
        vuln = json.loads(vuln_line.strip())
    except json.JSONDecodeError:
        print_error("The file's format is probably not JSONL, but XML or CSV")
        sys.exit(1)
    
    return vuln

# Append a custom field to the dictionary of unique custom fields.
def append_custom_field(unique_custom_fields, custom_field):
    cf_name = custom_field["name"]
    a_custom_field = Custom_Field(custom_field)
    unique_custom_fields[cf_name] = a_custom_field
    
# Process an array of custom fields in a vulnerability.
def process_custom_fields(unique_custom_fields, custom_fields):
    
    # Process one custom field at a time.
    for custom_field in custom_fields:
        cf_name = custom_field["name"]

        logging.debug(f"Processing custom field: {cf_name}")
        if cf_name in unique_custom_fields:
            unique_custom_field = unique_custom_fields[cf_name]
            if unique_custom_field.custom_field_id != custom_field["custom_field_definition_id"]:
                print_error(f"IDs for custom field {cf_name} do not match.  " +
                            f"{unique_custom_field.custom_field_id}, {custom_field['custom_field_definition_id']}")
            unique_custom_field.append_new_value(custom_field["value"])
        else:
            append_custom_field(unique_custom_fields, custom_field)

# Process vulnerabilities in the JSONL format.
def process_vuln_export(jsonl_vuln_file_name, unique_custom_fields):
    print_info(f"Opening {jsonl_vuln_file_name} for processing.")
    logging_interval = 1000

    # Open the JSONL file and read it line by line, checking each vulnerability line for custom fields.
    with open(jsonl_vuln_file_name, 'r') as jsonl_f:
        for line_num, vuln_line in enumerate(jsonl_f):
            vuln = convert_to_json(vuln_line)
            if "custom_fields" in vuln:
                logging.info(f"Found custom_field in Vuln {line_num}")
                process_custom_fields(unique_custom_fields, vuln["custom_fields"])
        
            if (line_num + 1) % logging_interval == 0:
                print(".", end='', flush='True')

    print("")
    return (line_num + 1)

# Write the information out to a CSV file.
def write_csv_file(custom_fields):
    # Open the CSV file and write the header row.
    csv_file_name = "uniq_custom_fields.csv"
    uniq_custom_fields_fp = open(csv_file_name, 'w', newline='')
    uniq_custom_field_writer = csv.writer(uniq_custom_fields_fp)
    uniq_custom_field_writer.writerow(["Custom Field", "Custom Field ID", "Field Count", "Value Count", "Custom Field Values"])

    # Process each custom field and write it to the CSV file.
    for custom_field_key in custom_fields:
        custom_field = custom_fields[custom_field_key]

        if custom_field.custom_field_count == 0:
            uniq_custom_field_writer.writerow([custom_field.custom_field_name, custom_field.custom_field_id, custom_field.custom_field_count])
        else:
            uniq_custom_field_writer.writerow([custom_field.custom_field_name, custom_field.custom_field_id,
                                               custom_field.custom_field_count, str(custom_field.get_num_values()), custom_field.get_values()])

    uniq_custom_fields_fp.close()
    print_info(f"{csv_file_name} is now available.")

if __name__ == "__main__":
    logging_file_name = "custom_fields.log"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO)
    print_info("List Unique Custom Fields")

    # Process command line arguments.
    id = 0
    try:
        if len(sys.argv) == 2:
            if sys.argv[1] == "-h":
                print_help()
            else:
                id = int(sys.argv[1])
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
               'User-Agent': 'list_custom_fields/1.0.0 (Kenna Security)'}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
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
    
    # A dictionary of custom fields keyed by custom field name with the value
    # of a custom field object.
    unique_custom_fields = {}
    vulns_processed = process_vuln_export(jsonl_vuln_file_name, unique_custom_fields)
    print_info(f"Total {vulns_processed} vulns processed.")
    
    num_uniq_custom_fields = len(unique_custom_fields)
    print_info(f"{num_uniq_custom_fields} unique custom fields discovered.")

    write_csv_file(unique_custom_fields)
