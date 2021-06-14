import os
import sys
import time
import math
import requests

# Might have to change this
base_url = "https://api.kennasecurity.com/assets"
ASSETS_PER_PAGE = 500

# 
def get_asset_page(page_num):
    page_param = "?page=" + str(page_num)
    url = base_url + page_param

    # Obtain the specified page.
    try:
        response = requests.get(url, headers=headers)
    except Exception as exp:
        print("List Asset Error: {str(exp)}")
        sys.exit(1)
    
    if response.status_code != 200:
        print(f"List Asset Error: {response.status_code}")
        print(f"Messages: {response.json()['message']}")
        sys.exit(1)
    
    return response.json()

# Obtain and write vulnerability information per asset ID into the specified file.
def get_vuln_info(api_key, vuln_url, asset_id, avfp, avlfp):
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key}

    vuln_url = "https://" + vuln_url
    try:
        response = requests.get(vuln_url, headers=headers)
        http_status_code = response.status_code

        # If too many requests, wait a second.  If is happens again, error out.
        if http_status_code == 429:
            time.sleep(1)
            response = requests.get(vuln_url, headers=headers)
            response.raise_for_status()

    except Exception as exp:
        print(f"Get vuln info error: {str(exp)}")
        return
    
    resp_json = response.json()
    
    vulns = resp_json['vulnerabilities']
    num_vulns = len(vulns)
    print(f"Vulnerabilities for asset ID {asset_id} ({num_vulns})", file=avlfp)
    for vuln in vulns:
        print(vuln, file=avfp)

    return num_vulns

if __name__ == "__main__":
    print("Vulnerabilities per Asset by Page")
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    headers = {'X-Risk-Token': api_key,
               'Accept': "application/json"
              }
    
    # Open files for vulnerabilities per asset, and vulnerabilites info based on search ID.
    avfp = open("asset_vuln_info", "w")
    avlfp = open("asset_vuln_log", "w")
    
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
    
    # Only a guess since all we know is the number of pages.
    asset_count = num_pages * ASSETS_PER_PAGE
    print(f"Will process between {asset_count - ASSETS_PER_PAGE} and {asset_count} assets.")
    
    asset_cntr = 0
    vuln_cntr = 0
    start_time = time.perf_counter()
    acc_start_time = start_time
    
    # Loop through all the assets one page a time, and get the vulnerabilities for each asset.
    while page_num <= num_pages:
        resp_json = get_asset_page(page_num)
        assets = resp_json['assets']
    
        # Adjust the total page count on the last page.
        page_asset_count = len(assets)
        if page_asset_count < ASSETS_PER_PAGE:
            asset_count = ((page_num - 1) * ASSETS_PER_PAGE) + page_asset_count
        
        # Get the vulnerabilities for each asset.
        for asset in assets:
            vuln_url = asset['urls']['vulnerabilities']
    
            vuln_cntr += get_vuln_info(api_key, vuln_url, str(asset['id']), avfp, avlfp)
            asset_cntr += 1
    
            # Do some timings and adjust estimated time left.
            if asset_cntr != 0 and asset_cntr % 5 == 0:
                time_lapse = time.perf_counter() - start_time
                if (time_lapse) < 1.0:
                    print(f"\nExceeded 5 API calls per second.")
                    time.sleep(1)
    
                if asset_cntr % 25 == 0:
                    time_left_secs = (asset_count - asset_cntr) / (time_lapse / 5)
                    print(f"Processed {asset_cntr} assets and {vuln_cntr} vulns. ({time_left_secs:0.1f}s  {time_left_secs/60:0.1f}m)   \r", end='')
    
                start_time = time.perf_counter()
    
        page_num += 1
    
    total_time_secs = time.perf_counter() - acc_start_time
    avfp.close()
    print(f"Processed {asset_cntr} assets and {vuln_cntr} vulns in {total_time_secs:0.1f}s  ({total_time_secs/60:0.1f}m)   ")
