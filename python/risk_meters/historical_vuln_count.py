# Get the historical vulnerability counts for each month for a year.
# The vulnerability counts for 'high', 'medium', and 'low' risk scores and include
# risk accepted vulnerability counts.
#
# This program is written to run stand-alone or as a subprocess invoked from list_risk_scores.py.

import os
import sys
from datetime import date
import requests
from prettytable import PrettyTable

# Obtain risk meter information by searching all the risk meters.
# There is no show asset group (risk meter) API.
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
            risk_meters[risk_meter['name']] = risk_meter['id']

    return risk_meters

# Obtains a historical asset group report as specifed by report from a start_date.
def get_historical_report(base_url, headers, id, report, start_date):
    get_report_url = f"{base_url}asset_groups/{id}/report_query/{report}?start_date={start_date}"

    # Invoke an Asset Group Report API.
    response = requests.get( get_report_url, headers=headers)
    if response.status_code != 200:
        print(f"Asset Group Report API Error: {response.status_code} with {get_report_url}")
        sys.exit(1)

    resp_json = response.json()
    return resp_json

# Processes vulnerability count report and accepted risk report.
def process_reports(base_url, headers, id, start_date, one_shot):
    vuln_count_report = "historical_open_vulnerability_count_by_risk_level"
    vuln_count_resp = get_historical_report(base_url, headers, id, vuln_count_report, start_date)

    accepted_risk_report = "risk_accepted_over_time"
    accepted_risk_resp = get_historical_report(base_url, headers, id, accepted_risk_report, start_date)

    # Verify asset group IDs
    if vuln_count_resp['id'] != accepted_risk_resp['id']: 
        print(f"Reports don't have matching IDs: {vuln_count_report['id']}, {accepted_risk_resp['id']}")
        sys.exit(1)
    
    if vuln_count_resp['id'] != id:
        print(f"Reports don't matching requested ID: {vuln_count_report['id']}, {id}")
        sys.exit(1)

    # Get to data as a dictionary of dates with each element containing low, medium, and high.
    vuln_count_data = vuln_count_resp['historical_vulnerability_count_by_risk']
    risk_accepted_data = accepted_risk_resp['risk_accepted_over_time']

    # Initialize output table.
    vuln_count_tbl = PrettyTable()
    vuln_count_tbl.field_names = ["Date", "High", "RA High", "Medium", "RA Medium", "Low", "RA Low"]

    # Process both vulnerability count and risk accepted vulnerability count data.
    for (vc_date, ra_date) in zip(vuln_count_data, risk_accepted_data):
        if vc_date != ra_date:
            print(f"Dates don't match: {vc_date} : {ra_date}")
            sys.exit(1)

        # Add today or the first of the month to the table.
        if one_shot or vc_date[-2:] == "01":
            vc_high = int(vuln_count_data[vc_date]['high'])
            vc_medium = int(vuln_count_data[vc_date]['medium'])
            vc_low = int(vuln_count_data[vc_date]['low'])
            ar_high = int(risk_accepted_data[ra_date]['high'])
            ar_medium = int(risk_accepted_data[ra_date]['medium'])
            ar_low = int(risk_accepted_data[ra_date]['low'])
   
            vuln_count_tbl.add_row([vc_date, vc_high, ar_high, vc_medium, ar_medium, vc_low, ar_low])
        
    print(vuln_count_tbl)
    print("")

def print_help(program):
    print(f"Prints out the historical risk meter vulnerability counts for a year.")
    print(f"{program} <risk meter name> [today]")
    print(f"   <risk meter name> - name of the risk meter")
    print(f"   [today] - if present will only print the vulnerability counts for today")
    print("")

if __name__ == "__main__":
    # Set the one_shot flag to False.
    one_shot = False
    check_risk_meter_name = True

    # Look for the risk meter name.
    if len(sys.argv) > 1:
        risk_meter_name = sys.argv[1]
    else:
        print("Requires risk meter name.")
        print_help(sys.argv[0])
        sys.exit(1)

    # Look for the "today" keyword which tells this program to do only
    # today and not monthly for a year.
    if len(sys.argv) > 2:
        if sys.argv[2] == "today":
            one_shot = True
        else:
            print("Currently only 'today' is supported.")
            print_help(sys.argv[0])
            sys.exit(1)

    # Check for arguments that could show if run as a subprocess.
    # If the paramters are invalid, ignore them and proceed.
    # If the parameters are valid, set the check_risk_meter_name to False.  This
    # reduces the number of API invokes.
    if len(sys.argv) > 3 and len(sys.argv) < 7:
        try:
            risk_meter_id = int(sys.argv[3])
            risk_meter_score = int(sys.argv[4])
            risk_accepted_score = int(sys.argv[5])
            check_risk_meter_name = False
        except ValueError:
            print(f"Invalid integer argument: {sys.argv[3]}, {sys.argv[4]}, {sys.argv[5]}")
            check_risk_meter_name = True

    # Only print the title if checking the risk meter name impling that this is not a subprocess.
    if check_risk_meter_name:
        print("")
        print("Historical Risk Meter Vulnerability Counts")
        print("")

    # To run this script, please assign your Kenna Risk Token to the KENNA_API_KEY environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)

    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.risk_meter_vuln_count/1.0.0 (Cisco Secure)'}

    # If one_shot True, then process only today, else process starting last year.
    today = date.today()
    if one_shot:
        start_date = today
    else:
        month_beginning = today.replace(day=1)
        start_date = month_beginning.replace(year=today.year - 1)
    start_date_str = start_date.isoformat()

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"

    risk_meters = {}
    if check_risk_meter_name:
        risk_meters = get_a_risk_meter(base_url, headers, risk_meter_name)
        if risk_meters == {}:
            print(f"{risk_meter_name} not found.")
            sys.exit(1)
    else:
        risk_meters[risk_meter_name] = risk_meter_id

    # Process the risk meter.
    for risk_meter_name in risk_meters.keys():
        id = risk_meters[risk_meter_name]
        
        if check_risk_meter_name:
            print(f"{risk_meter_name} ({risk_meters[risk_meter_name]})")
        else:
            print(f"{risk_meter_name} ({risk_meters[risk_meter_name]})  [{risk_meter_score}, {risk_accepted_score}]")
        print("Vulnerability Counts and Risk Accepted (RA) Vulnerability Counts")

        process_reports(base_url, headers, id, start_date_str, one_shot)
 