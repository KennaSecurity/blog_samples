# Creates a risk meter if the site of the asset is not already created.

import os
import sys
import json
import requests

# Collect the site risk meters.  Unfortunately, there is no risk meter search, so have to
# do a risk meter search and client process the return data looking at the risk meter name.
# Only risk meters with " Site" in their name are cached locally.
def get_site_risk_meters(base_url, headers):
    sites = []
    list_url = base_url + "asset_groups"

    page_num = 1
    page_param = "?page=" + str(page_num) + "&per_page=100"
    url = list_url + page_param

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Search Assets Error: {response.status_code} with {url}")
        sys.exit(1)
    
    resp_json = response.json()
    meta = resp_json['meta']
    num_pages = meta['pages']
    if num_pages > 20:
        print(f"There are over 2,000 risk meters that have the 'site:' tag.")
        print("The first 2,000 assets will be processed.")
        num_pages = 20
    print(f"Number of risk meter pages: {num_pages}")

    asset_groups = resp_json['asset_groups']
    for asset_group in asset_groups:
        risk_meter_name = asset_group['name']
        if " Site" in risk_meter_name:
            site_name = risk_meter_name.rsplit(' ', 1)[0]
            sites.append(site_name)

    page_num += 1
    while page_num <= num_pages:
        page_param = "?page=" + str(page_num) + "&per_page=100"
        url = list_url + page_param

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Search Assets Error: {response.status_code} with {url}")
            sys.exit(1)
    
        resp_json = response.json()

        asset_groups = resp_json['asset_groups']
        for asset_group in asset_groups:
            name = asset_group['name']
            if " Site" in name:
                sites.append(name)

        page_num += 1

    return sites

# Use the search asset API to obtain all the assets that
# contain the 'site:' an asset tag.
def get_site_assets(base_url, headers):

    # Query for all tags with "site:", tag:site\:*
    query_string = "?q=tag%3Asite%5C%3A%2A"
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
        print(f"There are over 10,000 assets that have the 'site::' tag.  Please use the export assets API.")
        print("The first 10,000 assets will be processed.")
        num_pages = 20
    print(f"Number of assets pages: {num_pages}")

    assets.extend(resp_json['assets'])

    page_num += 1
    while page_num <= num_pages:
        page_param = "&page=" + str(page_num)
        url = search_url + page_param

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Search Assets Error: {response.status_code} with {url}")
            sys.exit(1)
    
        resp_json = response.json()
        assets.extend(resp_json['assets'])
        page_num += 1

    return assets

# Obtain the site tag and return it.
def get_site_tag(tags):
    site_tag_filter = filter(lambda tag: 'site:' in tag, tags)
    site_tag = list(site_tag_filter)[0]
    return site_tag

# Forge a site name from site_tag.
def site_tag_to_site_name(site_tag):
    # Forge the site name from the site tag and use to as the risk meter asset query sting.
    site_tag_parts = site_tag.split()
    site_name = ' '.join(site_tag_parts[1:])
    return site_name

# Create a risk meter based on a site name.
# The risk meter name is site_name + " Site".
def create_risk_meter(site_name, base_url, headers):

    # Forge the risk meter asset query string.
    site_tag_for_query = "site: " + site_name
    print(f"{site_name} -> site tag for query: {site_tag_for_query}")
    risk_meter_name = site_name + " Site"

    asset_query = {
        "status": ["active"],
        "tags": [site_tag_for_query]
    }

    asset_group_data = {
        "asset_group": {
            "name": risk_meter_name,
            "query": asset_query
        }
    }

    url = base_url + "asset_groups"
    
    response = requests.post(url, headers=headers, data=json.dumps(asset_group_data))
    if response.status_code != 201:
        print(f"Create Risk Meter Error: {response.status_code} with url: {url}")
        sys.exit(1)
    
    resp_json = response.json()
    risk_meter = resp_json['asset_group']

    return risk_meter

if __name__ == "__main__":
    print("Update Site Risk Meters")

    # Obtain the Kenna Security API key from an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)
    
    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.update_site_risk_meter/1.0.0 (Cisco Secure)'}
    
    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    sites = get_site_risk_meters(base_url, headers)
    print(f"Number of current sites: {len(sites)}")
    
    assets = get_site_assets(base_url, headers)
    print(f"Number of qualified assets: {len(assets)}")
    
    # For each asset, check the tags for 'site'.
    # Verify if the Site exists in the `sites` cache.
    # If not, create a new risk meter.
    is_risk_meter_created = False
    for asset in assets:
        tags = asset['tags']
        site_tag = get_site_tag(tags)
        site_name = site_tag_to_site_name(site_tag)

        if not site_name in sites:
            risk_meter = create_risk_meter(site_name, base_url, headers)
            print(f"Created risk meter: {risk_meter['name']} - {risk_meter['id']}")
            sites.append(site_name)
            is_risk_meter_created = True

    if not is_risk_meter_created:
        print(f"No risk meters created.")
