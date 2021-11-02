import os
import sys
import csv
import time
import requests

# Obtain risk meter information by searching all the risk meters.
def get_a_risk_meter(base_url, headers, risk_meter_name):
    risk_meters = {}
    list_risk_meters_url = f"{base_url}asset_groups"

    # Invoke the List Asset Groups (Risk Meters) API.
    response = requests.get(list_risk_meters_url, headers=headers)
    if response.status_code != 200:
        print(f"List Risk Meters Error: {response.status_code} with {list_risk_meters_url}")
        sys.exit(1)

    resp_json = response.json()
    risk_meters_resp = resp_json['asset_groups']

    # Search for the risk meter by name.
    for risk_meter in risk_meters_resp:
        if risk_meter['name'] == risk_meter_name:
            risk_meters[risk_meter['name']] = risk_meter['querystring']

    return risk_meters

# Obtain the vulnerabilities information for an asset.  Return open vulnerabilities with
# risk_meter_score greater or equal to a specification.
def get_vuln_info(vuln_url, headers, risk_meter_score_fence, vulns_writer):
    vulns_to_process = []
    vuln_url = f"https://{vuln_url}"

    # Invoke the provided Show Asset Vulnerabilites API.
    response = requests.get(vuln_url, headers=headers)
    http_status_code = response.status_code

    # If too many requests, wait a second.  If is happens again, error out.
    if http_status_code == 429:
        time.sleep(1)
        response = requests.get(vuln_url, headers=headers)
        if response.status_code != 200:
            print(f"Show Asset Vulnerabilities Error: {response.status_code} with {vuln_url}")
            sys.exit(1)

    resp_json = response.json()
    vulns_resp = resp_json['vulnerabilities']

    # Go through the vulnerabilities filtering on open vulnerabilities and risk meter score.
    for vuln in vulns_resp:
        if not vuln['closed'] and vuln['risk_meter_score'] >= risk_meter_score_fence:
            vulns_to_process.append(vuln)

    # If nothing to process, then leave.
    if len(vulns_to_process) == 0:
        return 0

    # Write vulnerability CSV header.
    vulns_writer.writerow(["CVE ID", "Priority", "Threat", "Severity", "Risk Meter Score", "Description"])

    # Write the vulnerability information to the provide CSV file.
    for vuln in vulns_to_process:
        cve_id = vuln['cve_id']
        priority = vuln['priority']
        threat = vuln['threat']
        severity = vuln['severity']
        risk_meter_score = vuln['risk_meter_score']
        cve_description = vuln['cve_description']
        #print(f"{cve_id} {priority} - {threat} - {severity} : {risk_meter_score} ({risk_meter_score_fence})")
        vulns_writer.writerow([cve_id, priority, threat, severity, risk_meter_score, cve_description])

    return len(vulns_to_process)
    
# Get the assets in a risk meter.
def get_assets_in_risk_meter(base_url, headers, query_string, risk_meter_score_fence, vulns_writer):
    max_allowed_pages = 20

    # Create the search URL with the provied query_string
    search_assets_url = f"{base_url}assets/search?{query_string}&per_page=5000"

    # Invoke the Search Assets API.
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
        print("There are more that 100,000 assets in the search.")
        print("The data needs to be exported and different code is required.")
        return

    vuln_count = 0

    # Get the vulnerabilities for the first page of assets.
    for asset in assets_resp:
        # Write the asset locator.
        vulns_writer.writerow([asset['locator']])

        vuln_url = asset['urls']['vulnerabilities']
        vuln_count += get_vuln_info(vuln_url, headers, risk_meter_score_fence, vulns_writer)

    asset_count = len(assets_resp)
    page_num = 2
    # If there are more pages, then retrieve them.
    while page_num > max_allowed_pages:
        search_assets_url += f"&page={page_num}"

        # Invoke the Search Assets API with appropriate page number.
        response = requests.get(search_assets_url, headers=headers)
        if response.status_code != 200:
            print(f"Search Assets Error: {response.status_code} with {search_assets_url}")
            sys.exit(1)

        # Obtain the asset information.
        resp_json = response.json()
        assets_resp = resp_json['assets']

        # Go through all the vulnerabilies and get vulnerabiliity information.
        for asset in assets_resp:
            vuln_url = asset['urls']['vulnerabilities']
            vuln_count += get_vuln_info(vuln_url, headers, risk_meter_score_fence, vulns_writer)

        asset_count += len(assets_resp)
        page_num += 1

    return (asset_count, vuln_count)

def print_help(program):
    print(f"Writes a CSV file of assets' vulnerabilities higher than a fence.")
    print(f"{program} <risk meter name> [risk meter score fence]")
    print(f"   <risk meter name>")
    print(f"   <risk meter score fence> (optional) Default is 0.")

# Obtains a numeric risk meter score from a command line parameter.
def get_risk_meter_score(input_arg):
    try:
        risk_meter_score = int(input_arg)
    except ValueError:
        print(f"risk meter score needs to be a number, not {input_arg}")
        sys.exit(1)

    return risk_meter_score

if __name__ == "__main__":
    if len(sys.argv) > 1:
        risk_meter_name = sys.argv[1]
    else:
        print("Requires risk meter name.")
        print_help(sys.argv[0])
        sys.exit(1)

    risk_meter_score_fence = 0
    if len(sys.argv) > 2:
        risk_meter_score_fence = get_risk_meter_score(sys.argv[2])
        if risk_meter_score_fence > 100:
            print("You probably won't see any vulnerabilities if risk_meter_score_fencee is over 100.")

    csv_file_name = "vulns_in_risk_meter.csv"

    print("Risk Meter Vulnerability Report")
    print("")

    # Obtain the Kenna Security API key from an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)

    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.risk_meter_report/1.0.0 (Cisco Secure)'}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"

    risk_meters = get_a_risk_meter(base_url, headers, risk_meter_name)
    if risk_meters == {}:
        print(f"{risk_meter_name} not found.")
        sys.exit(1)

    # Open up the CSV file.
    vulns_in_risk_meter_fp = open(csv_file_name, 'w', newline='')
    vulns_writer = csv.writer(vulns_in_risk_meter_fp)
        
    # Process the risk meter.
    for risk_meter_name in risk_meters.keys():
        # Write risk meter title.
        vulns_writer.writerow([f"Vulnerabilities for Risk Meter {risk_meter_name} score over {risk_meter_score_fence}"])
        vulns_writer.writerow([])

        query_string = risk_meters[risk_meter_name]
        print(f"Processing: {risk_meter_name} with {query_string}: ", end='')
        (num_assets, num_vulns) = get_assets_in_risk_meter(base_url, headers, query_string,
                                                           risk_meter_score_fence, vulns_writer)
        print(f"{num_assets} assets with {num_vulns} vulnerabilities")
        vulns_writer.writerow([])
