import os
import sys
import json
import requests

def print_json(json_obj):
    print(json.dumps(json_obj, sort_keys=True, indent=2))

# Get the CISA catalog.
def get_cisa_catalog(headers):
    cisa_catalog = {}
    get_cisa_catalog_url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    response = requests.get(get_cisa_catalog_url, headers=headers)
    if response.status_code != 200:
        print(f"List CISA Catalog Error: {response.status_code} with {get_cisa_catalog_url}")
        sys.exit(1)

    resp_json = response.json()
    title = resp_json['title']
    date_released = resp_json['dateReleased']
    num_vulns = resp_json['count']

    print(f"{title}")
    print(f"{num_vulns} vulnerabilities on {date_released}")

    return resp_json['vulnerabilities']

if __name__ == "__main__":
    print("Get CISA Catalog")
    print("")

    # HTTP headers.
    headers = { 'Content-Type': 'application/json; charset=utf-8' }
               
    vulns = get_cisa_catalog(headers)
    print_json(vulns)

    print("")
    print(f"Number of vulns: {len(vulns)}")
