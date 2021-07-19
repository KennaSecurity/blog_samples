# Creates a risk meter if an asset Business Unit (bu) is not in the 
# business unit file.

import os
import sys
import json
import requests

# Read the business units already found business units(bus) from  a file.
def get_business_units_from_file(bu_file_name):
    bus = []

    try:
        with open(bu_file_name, "r") as bu_f:
            file = bu_f.readlines()
    except FileNotFoundError as fnfe:
        print(f"The file {bu_file_name} was not found.")
        return bus
    except IOError as ioe:
        print(f"Unexpected I/O error: {sys.exc_info()[0]}")
        sys.exit(1)

    for line in file:
        bus.append(line.rstrip('\n'))

    print(f"BUs: {bus}")
    return bus

# Write the business units out to a file.
def set_business_units_to_file(bu_file_name, bus):

    try:
        with open(bu_file_name, "w") as bu_f:
            for bu in bus:
                bu_f.write(f"{bu}\n")
    except IOError as ioe:
        print(f"Unexpected I/O error: {sys.exc_info()[0]}")
        sys.exit(1)
    return bus

# Use the search asset API to obtain all the assets that
# contain the 'bu:' an asset tag.
def get_business_unit_assets(base_url, headers):

    # Query for all tags with "bu:", tag:bu\:*
    query_string = "?q=tag%3Abu%5C%3A%2A"
    search_url = base_url + "assets/search" + query_string

    assets = []
    page_num = 1
    page_param = "&page=" + str(page_num)
    url = search_url + page_param

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Search Assets Error: {response.status_code} with {url}")
        sys.exit(1)
    
    resp_json = response.json()
    meta = resp_json['meta']
    num_pages = meta['pages']
    if num_pages > 20:
        print(f"There are over 10,000 assets that have the 'bu:' tag.  Please use the export assets API.")
        print("The first 10,000 assets will be processed.")
        num_pages = 20
    print(f"Number of pages: {num_pages}")

    assets.extend(resp_json['assets'])

    page_num += 1
    while page_num <= num_pages:
        page_param = "?&page=" + str(page_num)
        url = search_url + page_param

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Search Assets Error: {response.status_code} with {url}")
            sys.exit(1)
    
        resp_json = response.json()
        assets.extend(resp_json['assets'])
        page_num += 1

    return assets

# Obtain the business unit tag and return it.
def get_business_unit_tag(tags):
    bu_tag_filter = filter(lambda tag: 'bu:' in tag, tags)
    bu_tag = list(bu_tag_filter)[0]
    return bu_tag

# Create a risk meter based on a business unit name.
def create_risk_meter(bu_tag, base_url, headers):
    bu_tag_parts = bu_tag.split()
    bu_name = bu_tag_parts[1]
    bu_tag_for_html_query = "bu: " + bu_name
    #bu_tag_for_html_query = "bu%5C%3A%20" + bu_name

    query = {
        "status": ["active"],
        "tags": [bu_tag_for_html_query]
    }

    asset_group = {
        "asset_group": {
            "name": bu_name + "_BU",
            "query": query
        }
    }

    url = base_url + "asset_groups"
    
    response = requests.post(url, headers=headers, data=json.dumps(asset_group))
    if response.status_code != 201:
        print(f"Create Risk Meter Error: {response.status_code} with url: {url}")
        sys.exit(1)
    
    resp_json = response.json()
    risk_meter = resp_json['asset_group']

    return risk_meter

if __name__ == "__main__":
    print("Update Risk Meters")

    bu_file_name = "business_units"
    business_units = get_business_units_from_file(bu_file_name)
    print(f"Number of current BUs: {len(business_units)}")
    
    # Obtain the Kenna Security API key from an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)
    
    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'webinar.update_risk_meter/1.0.0 (Cisco Secure)'}
    
    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    assets = get_business_unit_assets(base_url, headers)
    print(f"Number of qualified assets: {len(assets)}")
    
    # For each asset, check the tags for 'bu'.
    # Verify if the BU exists in the `business_units` cache.
    # If not, create a new risk meter.
    is_risk_meter_created = False
    for asset in assets:
        tags = asset['tags']
        bu_tag = get_business_unit_tag(tags)

        if not bu_tag in business_units:
            risk_meter = create_risk_meter(bu_tag, base_url, headers)
            print(f"Created risk meter: {risk_meter['name']} - {risk_meter['id']}")
            business_units.append(bu_tag)
            is_risk_meter_created = True

    set_business_units_to_file(bu_file_name, business_units)

    if not is_risk_meter_created:
        print(f"No risk meters created.")
