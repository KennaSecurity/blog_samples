import os
import sys
import requests

# Might have to change this
base_url = "https://api.kennasecurity.com/assets"

def get_asset_page(page_num):
    page_param = "?page=" + str(page_num)
    url = base_url + page_param
    
    # Obtain the specified page.
    try:
        response = requests.get(url, headers=headers)
    except Exception as exp:
        print("List Asset Error: " + exp.__str__())
        sys.exit(1)
    
    if response.status_code != 200:
        print(f"List Asset Error: {response.status_code}")
        print(f"Messages: {response.json()['message']}")
        sys.exit(1)
    
    return response.json()

# main
print("List Assets by Page")
api_key = os.getenv('KENNA_API_KEY')
if api_key is None:
    print("Environment variable KENNA_API_KEY is non-existent")
    sys.exit(1)

headers = {'X-Risk-Token': api_key,
           'Accept': "application/json"
          }

max_allowed_pages = 20
asset_count = 0
page_num = 1

# Obtain the first page.
resp_json = get_asset_page(page_num)

# Determine the number of pages and print an appropriate error message.
meta = resp_json['meta']
num_pages = meta['pages']
if num_pages > max_allowed_pages:
    print(f"Number of pages = {num_pages} which exceeds the maximum allowed of {max_allowed_pages}")
    print("Will only output the first 10,000 assets.")
    num_pages = max_allowed_pages


# Loop through all the assets one page at a time, while counting assets.
while page_num <= num_pages:
    resp_json = get_asset_page(page_num)
    assets = resp_json['assets']
    print(f"Number of assets: {len(assets)}")
    asset_count += len(assets)
    page_num += 1

print(f"Total number of assets = {asset_count}")

