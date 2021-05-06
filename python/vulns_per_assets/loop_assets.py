import os
import sys
import requests

print("List Assets")
api_key = os.getenv('KENNA_API_KEY')
if api_key is None:
    print("Environment variable KENNA_API_KEY is non-existent")
    sys.exit(1)

headers = {'X-Risk-Token': api_key,
           'Accept': "application/json"
          }

asset_total = 0
max_pages = 20
base_url = "https://api.kennasecurity.com/assets"

for page_num in range(1, max_pages+1):
    page_param = "?&page=" + str(page_num)
    url = base_url + page_param

    print(url)
    response = requests.get(url, headers=headers)
    resp_json = response.json()
    assets = resp_json['assets']
    if len(assets) == 0:
        break
    asset_total += len(assets)
    print(f"Number of assets: {len(assets)}")
    
print(f"Total number of assets = {asset_total}")

