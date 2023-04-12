# List custom field definitions.
#

import os
import sys
import requests
from prettytable import PrettyTable

# Get custom field definition information, and return a dictionary of tuples containing custom field definition ID,
# custom field definition score, and last update time.
def get_custom_field_defs(base_url, headers):
    custom_field_defs = {}
    list_custom_field_defs_url = f"{base_url}/custom_field_definitions"

    response = requests.get(list_custom_field_defs_url, headers=headers)
    if response.status_code != 200:
        print(f"List Custom Field Defintions Error: {response.status_code} with {list_custom_field_defs_url}")
        sys.exit(1)

    resp_json = response.json()
    custom_field_defs_resp = resp_json['custom_field_definitions']

    for custom_field_def in custom_field_defs_resp:
        custom_field_def_id = custom_field_def['id']
        custom_field_def_data_type = custom_field_def['data_type']
        custom_field_def_entity_type = custom_field_def['definition_entity_type']
        custom_field_def_facet = custom_field_def['facet']

        custom_field_defs[custom_field_def['name']] = (custom_field_def_id,
                                                       custom_field_def_data_type,
                                                       custom_field_def_entity_type,
                                                       custom_field_def_facet)

    return custom_field_defs

if __name__ == "__main__":
    print("List Custom Field Definitions")
    print("")

    # Obtain the Kenna Security API key from an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)

    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.list_custom_field_definitions/1.0.0 (Cisco Secure)'}

    # You might have to change this depending on your deployment.
    v2_base_url = "https://api.kennasecurity.com/v2"

    custom_field_defs = get_custom_field_defs(v2_base_url, headers)

    print("")
    print("Custom Field Definitions")

    custom_field_def_tbl = PrettyTable()
    custom_field_def_tbl.field_names = ["Name", "ID", "Data Type", "Entity Type", "Facet"]
    custom_field_def_tbl.align["Name"] = "l"

    # Loop through all the custom field definitions (cdf) and add table row.
    for custom_field_def_name in custom_field_defs.keys():
        cfd_tuple = custom_field_defs[custom_field_def_name]
        cfd_id =  cfd_tuple[0]
        cfd_data_type =  cfd_tuple[1]
        cfd_entity_type = cfd_tuple[2]
        cfd_facet = cfd_tuple[3]

        custom_field_def_tbl.add_row([custom_field_def_name, cfd_id, cfd_data_type, cfd_entity_type, cfd_facet])

    print(custom_field_def_tbl)
    print("")

