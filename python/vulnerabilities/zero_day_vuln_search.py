import os
import sys
import json
import requests

VERSION = "1.0.0"

# Process an HTTP error by printing and log.error
def process_http_error(msg, response, url):
    if response.text is None:
        print(f"{msg} HTTP Error: {response.status_code} with {url}")
    else:
        print(f"{msg}, {url} status_code: {response.status_code} info: {response.text}")

# Performs a search for vulnerabilities with zero day information.
def search_vulns_for_zero_day(base_url, headers):
    search_vulns_url = f"{base_url}/vulnerabilities/search"

    query_params = "?zero_day[]=true&fields=id,created_at,identifiers,last_seen_time,cve_id,description"
    search_vulns_url += query_params

    response = requests.get(search_vulns_url, headers=headers)
    if response.status_code != 200:
        process_http_error(f"Vulnerability Search API Error", response, search_vulns_url)
        sys.exit(1)

    return response.json()

# Obtains the Talos zero day data.
def get_vuln_data(base_url, headers, vuln_id):
    show_vuln_url = f"{base_url}/vulnerabilities/{vuln_id}"

    response = requests.get(show_vuln_url, headers=headers)
    if response.status_code != 200:
        process_http_error(f"Show Vulnerability API Error", response, show_vuln_url)
        sys.exit(1)

    vuln_resp = response.json()
    return vuln_resp['vulnerability']

# Checks if a Talos report URL exists.
def talos_url_exists(talos_id):
    talos_vuln_url = f"https://www.talosintelligence.com/vulnerability_reports/{talos_id}"

    try:
        response = requests.get(talos_vuln_url)
        if response.status_code == 200:
            return talos_vuln_url
    except:
        pass

    return None

def print_vuln_info(vuln_data):
    vuln_id = vuln_data['id']
    identifers = vuln_data['identifiers']

    print(f"Vuln ID: {vuln_id}, Created at: {vuln_data['created_at']}, Last Seet at: {vuln_data['last_seen_time']}")
    print(f"CVE ID: {vuln_data['cve_id']}")
    if "identifiers" in vuln_data and len(identifers) > 0:
        print("Indentifers: ", end='')
        print(*identifers, sep=',')
    print(f"Description: {vuln_data['description']}")
    print(f"Asset ID: {vuln_data['asset_id']}")

    if "solution" in vuln_data and not vuln_data['solution'] is None:
        print(f"solution: {vuln_data['solution']}")

def print_talos_data(vuln_data):
    if not "talos_zero_day" in vuln_data:
        print(f"Talos zero day data is not present")
        return 

    zero_day_data = vuln_data['talos_zero_day']
    print(f"Talos ID: {zero_day_data['talos_id']}, CVE ID: {zero_day_data['cve']}, {zero_day_data['cvss']}")
    for cpe in zero_day_data['cpes']:
        print(f"cpe: {cpe}")
    for snort_rule in zero_day_data['snort_rules']:
        print(f"snort_rule: {snort_rule}")
    if not (talos_url := talos_url_exists(zero_day_data['talos_id'])) is None:
        print(f"Talos Report URL: {talos_url}")

def print_cvss3_info(vuln_data):
    if not "cvss_v3" in vuln_data or vuln_data['cvss_v3'] is None:
        return

    cvss_v3_data = vuln_data['cvss_v3']
    print(f"CVSS v3 score: {cvss_v3_data['score']}, exploit score: {cvss_v3_data['expoloit_score']}")
    print(f"CVSS v3 impact score: {cvss_v3_data['impact_score']}, temporal score: {cvss_v3_data['temporal_score']}")

if __name__ == "__main__":

    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print(f"Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    user_agent = f"search_vulns_for_zero_day/{VERSION} (Kenna Security)"
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key,
               'User-Agent': user_agent}

    # You might have to change this depending on your deployment.
    base_url = "https://api.us.kennasecurity.com"
    
    zero_day_resp = search_vulns_for_zero_day(base_url, headers)
    zero_day_vulns = zero_day_resp['vulnerabilities']
    print(f"Number of zero day vulns: {len(zero_day_vulns)}\n")

    for vuln_count, vuln_data in enumerate(zero_day_vulns, start=1):

        vuln_data = get_vuln_data(base_url, headers, vuln_data['id'])
        
        print(f"---{vuln_count}----------------------------------------------")
        print_vuln_info(vuln_data)
        print_talos_data(vuln_data)
        print_cvss3_info(vuln_data)

    print(f"---------------------------------------------------")
