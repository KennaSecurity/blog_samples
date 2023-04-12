# Add a custom field to vulnerabilities via a CSV file.
#
# This script requires one command line parameter: the input CSV file name.
# The CSV file contains the custom field defintion parameters, the custom field value,
# and the vulnerability ID to update.

import os
import sys
import csv
import json
import requests

# Dump JSON is a readable format.
def print_json(json_obj):
    print(json.dumps(json_obj, sort_keys=True, indent=2))

def print_http_error(error_string, http_status_code, resp_json):
    print(f"{error_string} {http_status_code}: {resp_json['message']}, {resp_json['error']}")
    return

# Create a dictionary of custom field defintions keyed by custom field defintion name.
def get_custom_field_definitions(base_url, headers):
    # Dictionary of custom field definitions.
    custom_field_defs = {}

    list_custom_field_defs_url = f"{base_url}custom_field_definitions"

    # List the the custom fields.  Only the first 100 with the code.
    response = requests.get(list_custom_field_defs_url, headers=headers)
    resp_json = response.json()
    if response.status_code != 200:
        print_http_error("List Risk Meters Error: ", response.status_code, resp_json)
        sys.exit(1)

    custom_field_defs_resp = resp_json['custom_field_definitions']

    # Create a custom field definition record from the API response.
    for cdf in custom_field_defs_resp:
        custom_field_def = {}
        custom_field_def['name'] = cdf['name']
        custom_field_def['id'] = cdf['id']
        custom_field_def['data_type'] = cdf['data_type']
        custom_field_def['entity_type'] = cdf['definition_entity_type']
        custom_field_def['facet'] = cdf['facet']

        # Add custom field definition records to custom field defintions keyed by name.
        custom_field_defs[cdf['name']] = custom_field_def

    return custom_field_defs

# Compare current custom field defintion obtained via the API, to the custom field defintion
# in the CSV file.
def compare_custom_field_defs(curr_cfd, csv_cfd):
    if curr_cfd['data_type'] != csv_cfd['data_type']:
        print(f"Data_types do not agree.  {curr_cfd['data_type']} != CVS {csv_cfd['data_type']}")
        sys.exit(1)
    if curr_cfd['entity_type'] != csv_cfd['entity_type']:
        print(f"Entity_types do not agree.  {curr_cfd['entity_type']} != CVS {csv_cfd['entity_type']}")
        sys.exit(1)

    return curr_cfd['id']

# Process the CSV input file custom field defintion dictionary.
# Return a dictionary of custom field defintions with custom field defintion parameters,
# custom field values, and vulnerability ID.
def process_input_file(csv_input_file_name):
    cdfs = {}

    try:
        with open(csv_input_file_name, newline='', mode='r', encoding='utf-8-sig') as input_file:
            reader = csv.DictReader(input_file, delimiter=',', skipinitialspace=True) 
            for row in reader:
                cdf_name = row['name']
                cdfs[cdf_name] = row

    except FileNotFoundError:
        print(f"ERROR: CSV input file, {csv_input_file_name} not found.")
        sys.exit(1)

    return cdfs

# Create a custom field defintion.
def create_custom_field_definition(base_url, headers, cfd_dict):
    create_url = f"{base_url}custom_field_definitions"

    payload = {}
    payload['name'] = cfd_dict['name']
    payload['description'] = cfd_dict['description']
    payload['data_type'] = cfd_dict['data_type']
    payload['definition_entity_type'] = cfd_dict['entity_type']
    payload['facet'] = cfd_dict['facet']
    if 'dropdown_options' in cfd_dict:
        payload['drop_down_options'] = cfd_dict['dropdown_options']

    response = requests.post(create_url, headers=headers, data=json.dumps(payload))
    resp_json = response.json()
    if response.status_code != 201:
        print_http_error("Create Custom Field Definition Error: ", response.status_code, resp_json)
        sys.exit(1)

    custom_field_def = resp_json['custom_field_definition']
    return custom_field_def['id']

# Update a custom field in a vulnerability.
def update_vuln(base_url, headers, vuln_id, custom_field_def_id, custom_field_value):
    vuln_id = vuln_id.strip()

    update_url = f"{base_url}vulnerabilities/{vuln_id}"
    update_custom_field_id = f"{custom_field_def_id}"
    update_data = {
        "vulnerability": {
            "custom_fields": {
                update_custom_field_id: custom_field_value
            }
        }
    }
    # print_json(update_data)

    # Invoke the update vulnerability endpoint.
    response = requests.put(update_url, headers=headers, data=json.dumps(update_data))
    resp_json = response.json()

    if response.status_code == 202:
        if f"{resp_json['id']}" == vuln_id:
            print(f"Updating vulnerability ID {vuln_id} in the background.")
        else:
            print(f"Vulnerability IDs don't match: response ID = '{resp_json['id']}', API ID = '{vuln_id}'")
            sys.exit(1)
    elif response.status_code == 204:
            print(f"Updated vulnerability ID {vuln_id}.")
    else:
        print_http_error("Vulnerability Update API Error: ", response.status_code, resp_json)
        sys.exit(1)
    
    return

if __name__ == "__main__":
    if len(sys.argv) < 2:
       print(f"{sys.argv[0]} csv_input_file")
       sys.exit(1)

    # Get the command line parameters.
    csv_input_file = sys.argv[1]

    print("Add Custom Field Definitions")
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("KENNA API key is non-existent")
        sys.exit(1)
    
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'add_custom_field_definitions/1.0.0 (Kenna Security)'}
    
    base_url = "https://api.kennasecurity.com/"
    v2_base_url = "https://api.kennasecurity.com/v2/"

    custom_field_defs = get_custom_field_definitions(v2_base_url, headers)
    print(f"{len(custom_field_defs)} custom field definitions exist.")

    # Holds all the custom field definitions from the CSV file.
    csv_custom_field_defs = process_input_file(csv_input_file)

    # Obtain all the rows in CSV file.  If custom field definition exists, then fetch the ID,
    # else create new custom field defintion.
    for key, csv_custom_field_def in csv_custom_field_defs.items():
        print(f"{key} -> {csv_custom_field_def}")
        
        if key in custom_field_defs:
            cfd_id = compare_custom_field_defs(custom_field_defs[key], csv_custom_field_def)
        else:
            cfd_id = create_custom_field_definition(v2_base_url, headers, csv_custom_field_def)
            print(f"{cfd_id} ID created for custom field definition {key}")
            csv_custom_field_def['id'] = cfd_id
            custom_field_defs[key] = csv_custom_field_def

        custom_value = csv_custom_field_def['value']
        vuln_id = csv_custom_field_def['vuln_id'] 

        update_vuln(v2_base_url, headers, vuln_id, cfd_id, custom_value)

    print("All pau")