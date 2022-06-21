# Update a custom field for one vulnerability.
#
# This script requires three command line parameters: the vulnerability ID,
# the custom field ID, and custom field value.

import os
import sys
import json
import requests

# Dump JSON is a readable format.
def print_json(json_obj):
    print(json.dumps(json_obj, sort_keys=True, indent=2))

# Update a custom field in a vulnerability.
def update_vuln(base_url, headers, vuln_id, custom_field_id, custom_field_value):
    update_url = f"{base_url}vulnerabilities/{vuln_id}"
    update_custom_field_id = f"{custom_field_id}"
    update_data = {
        "vulnerability": {
            "custom_fields": {
                update_custom_field_id: custom_field_value
            }
        }
    }

    print(f"Update URL: {update_url}")
    print_json(update_data)

    # Invoke the update vulnerability endpoint.
    response = requests.put(update_url, headers=headers, data=json.dumps(update_data))
    if response.status_code != 204:
        print("Vulnerability Update API ", response, update_url)
        sys.exit(1)
    
if __name__ == "__main__":
    if len(sys.argv) < 4:
       print(f"{sys.argv[0]} <vuln_id> <custom field name> <custom field value>")
       sys.exit(1)

    # Get the command line parameters.
    vuln_id = sys.argv[1]
    custom_field = sys.argv[2]
    custom_value = sys.argv[3]

    print("Update Vulnerability Custom Field")
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("KENNA API key is non-existent")
        sys.exit(1)
    
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'update_vuln_custom_field/1.0.0 (Kenna Security)'}
    
    base_url = "https://api.kennasecurity.com/"

    update_vuln(base_url, headers, vuln_id, custom_field, custom_value)
