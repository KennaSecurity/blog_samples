# Search for custom fields in vulnerabilities.
#
# The script requires two command line paramters, the custom field name, and the 
# custom field value.  There is no wildcarding.

import os
import sys
import json
import requests

# Dumps JSON.  Great for debugging.
def print_json(json_obj):
    print(json.dumps(json_obj, sort_keys=True, indent=2))

def search_vuln(base_url, headers, curr_page, num_pages, custom_field_query):
    # Set up the search vulnerability endpoing URL.
    page_size_query = f"per_page={page_size}&page={curr_page}"

    search_url = f"{base_url}vulnerabilities/search?{page_size_query}&{custom_field_query}"
    print(f"URL: {search_url}")
    print("-----")
    
    # Invoke search vulnerability.
    response = requests.get(search_url, headers=headers)
    resp_json = response.json()
    if response.status_code != 200:
        print(f"Search Vulns Error: {response.status_code} with {search_url}")
        print_json(resp_json)
        sys.exit(1)
    
    vulns = resp_json['vulnerabilities']
    meta = resp_json['meta']
    
    # List the vulns that contain the custom field name and value.
    for vuln in vulns:
        print(f"Vuln: {vuln['id']}  CVE: {vuln['cve_id']}  {vuln['status']} - Asset ID: {vuln['asset_id']}")
        print(f"{vuln['cve_description']}")
        if len(vuln['custom_fields']) > 0:
            custom_fields = vuln['custom_fields']
            for custom_field in custom_fields:
                if custom_field['name'] == search_custom_field:
                    print_json(custom_field)
        print("-----")

    return(meta['pages'], len(vulns))

if __name__ == "__main__":
    if len(sys.argv) < 3:
       print(f"{sys.argv[0]} <custom field name> <custom field value>")
       sys.exit(1)

    search_custom_field = sys.argv[1]
    search_value = sys.argv[2]

    print("Search Vulnerabilities with Custom Fields")
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("KENNA API key is non-existent")
        sys.exit(1)
    
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'search_vulns_with_custom_fields/1.0.0 (Kenna Security)'}
    
    base_url = "https://api.kennasecurity.com/"

    # Our initialized variables.
    page_size = 5000
    curr_page = 1
    num_pages = 1
    total_vuln_count = 0
    print("-----")

    # Dynamic custom field query parameter.
    custom_field_query = f"custom_fields:{search_custom_field}[]={search_value}"

    while curr_page <= num_pages:
        (num_pages, vuln_count) = search_vuln(base_url, headers, curr_page, num_pages, custom_field_query)
        total_vuln_count += vuln_count
        curr_page += 1

    print(f"Number of vulnerabilities: {total_vuln_count}")

