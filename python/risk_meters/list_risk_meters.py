import os
import sys
import requests
from prettytable import PrettyTable

# Get risk meter information, and return a dictionary of tuples containing risk meter ID,
# risk meter score, and last update time.
def get_risk_meters(base_url, headers):
    risk_meters = {}
    list_risk_meters_url = f"{base_url}asset_groups"

    response = requests.get(list_risk_meters_url, headers=headers)
    if response.status_code != 200:
        print(f"List Risk Meters Error: {response.status_code} with {list_risk_meters_url}")
        sys.exit(1)

    resp_json = response.json()
    risk_meters_resp = resp_json['asset_groups']

    for risk_meter in risk_meters_resp:
        risk_meter_id = risk_meter['id']
        risk_meter_score = risk_meter['risk_meter_score']
        updated_at = risk_meter['updated_at']
        query_string = risk_meter['querystring']
        risk_meters[risk_meter['name']] = (risk_meter_id, risk_meter_score, updated_at, query_string)

    return risk_meters

# Obtain and return the number of assets in a risk meter.
def get_assets_in_risk_meter(base_url, headers, query_string):
    max_allowed_pages = 20

    # Create the search URL with the provied query_string
    search_assets_url = f"{base_url}assets/search?{query_string}&per_page=5000"

    # Invoke the search API.
    response = requests.get(search_assets_url, headers=headers)
    if response.status_code != 200:
        print(f"Search Assets Error: {response.status_code} with {search_assets_url}")
        sys.exit(1)

    # Obtain the asset information.
    resp_json = response.json()
    assets_resp = resp_json['assets']

    # Suss-out page information
    meta = resp_json['meta']
    num_pages = meta['pages']
    if num_pages > max_allowed_pages:
        return 100000

    asset_count = len(assets_resp)
    page_num = 2
    while page_num > max_allowed_pages:
        search_assets_url += f"&page={page_num}"

        # Invoke the search API.
        response = requests.get(search_assets_url, headers=headers)
        if response.status_code != 200:
            print(f"Search Assets Error: {response.status_code} with {search_assets_url}")
            sys.exit(1)

        # Obtain the asset information.
        resp_json = response.json()
        assets_resp = resp_json['assets']

        asset_count += len(assets_resp)
        page_num += 1

    return asset_count

if __name__ == "__main__":
    print("List Risk Meters")
    print("")

    # Obtain the Kenna Security API key from an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)

    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.list_risk_meters/1.0.0 (Cisco Secure)'}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"

    risk_meters = get_risk_meters(base_url, headers)

    print("")
    risk_meter_tbl = PrettyTable()
    risk_meter_tbl.field_names = ["Risk Meter Name", "ID", "Count", "Score", "Last Updated"]
    risk_meter_tbl.align["Risk Meter Name"] = "l"

    for risk_meter_name in risk_meters.keys():
        risk_meter_tuple = risk_meters[risk_meter_name]
        risk_meter_id = risk_meter_tuple[0]
        risk_meter_score = risk_meter_tuple[1]
        updated_at = risk_meter_tuple[2]
        query_string = risk_meter_tuple[3]

        #print(f"Processing: {risk_meter_name} with score {risk_meter_score}.")
        num_assets = get_assets_in_risk_meter(base_url, headers, query_string)
        risk_meter_tbl.add_row([risk_meter_name, risk_meter_id, num_assets, risk_meter_score, updated_at])

    print(risk_meter_tbl)
    print("")


