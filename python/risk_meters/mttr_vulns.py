# Get the historical vulnerability counts for each month for a year.
# The vulnerability counts for 'high', 'medium', and 'low' risk scores and include
# risk accepted vulnerability counts.
#
# This program is written to run stand-alone or as a subprocess invoked from list_risk_scores.py.

import os
import sys
import calendar
from datetime import date, timedelta
import requests
from prettytable import PrettyTable

def sign_bit(num):
    return (int(num < 0))

def get_next_month(year, month):
    month_day = calendar.monthrange(year, month)
    num_days_per_month = month_day[1]
    month_delta = timedelta(days=num_days_per_month)

    month_first_day = date(year, month, 1)
    next_month_first_day = month_first_day + month_delta

    return (next_month_first_day.year, next_month_first_day.month)

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

# Obtains an MTTR asset group report as specifed by report from a start and end dates.
def get_mttr_report(base_url, headers, id, report, start_date, end_date):
    if report == "vulns" or report == "vulnerabilities":
        get_report_url = f"{base_url}asset_groups/{id}/report_query/historical_mean_time_to_remediate_by_risk_level"
    else:
        get_report_url = f"{base_url}asset_groups/{id}/report_query/{report}/historical_mean_time_to_remediate_by_risk_level"
    get_report_url += f"?start_date={start_date}&end_date={end_date}"

    # Invoke an Asset Group Report API.
    response = requests.get( get_report_url, headers=headers)
    if response.status_code != 200:
        print(f"Asset Group MTTR Report API Error: {response.status_code} with {get_report_url}")
        sys.exit(1)

    resp_json = response.json()
    return resp_json

# Obtains a vuln MTTR asset group report from the start and end dates.
def get_vuln_mttr_report(base_url, headers, id, start_date, end_date):
    vuln_mttr_report = "vulns"
    vuln_mttr_resp = get_mttr_report(base_url, headers, id, vuln_mttr_report, start_date, end_date)

    if vuln_mttr_resp['id'] != id:
        print(f"Reports ID doesn't match requested ID: {vuln_mttr_report['id']}, {id}")
        sys.exit(1)

    return vuln_mttr_resp['mttr']
    
# Processes vulnerability MTTR report.
def process_report(base_url, headers, name, id, given_date, months_back, num_months):

    # Look up array
    months = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    
    year = given_date.year
    month = given_date.month

    # Surprisely, this works due to Python allowing negative array indexes.
    start_month_index = month - months_back
    year_to_process = year -  sign_bit(start_month_index)
    month_to_process = months[start_month_index]

    vuln_mttr_tbl = PrettyTable()
    vuln_mttr_tbl.field_names = ["Date", "High Risk", "Medium Risk", "Low Risk", "All"]

    # Get and process vuln MTTR data for each month.
    for i in range(0, num_months):
        start_date = date(year_to_process, month_to_process, 1)
        month_info = calendar.monthrange(year_to_process, month_to_process)
        end_date = date(year_to_process, month_to_process, month_info[1])

        # Invoke API for MTTR information.
        vuln_risk_levels = get_vuln_mttr_report(base_url, headers, id, start_date, end_date)

        # Format date.
        start_date_str = start_date.strftime("%Y-%m-%d")
        end_date_str = end_date.strftime("%Y-%m-%d")
        date_str = f"{start_date_str} -> {end_date_str}"

        # Get Risk values.
        total_vulns = vuln_risk_levels['All vulnerabilities']
        high_risk = vuln_risk_levels['High risk']
        medium_risk = vuln_risk_levels['Medium risk']
        low_risk = vuln_risk_levels['Low risk']

        vuln_mttr_tbl.add_row([date_str, high_risk, medium_risk, low_risk, total_vulns])

        (year_to_process, month_to_process) = get_next_month(year_to_process, month_to_process)

    print("")
    print(f"Historical Vulnerabilities MTTR in Days for Risk Meter {name} ({id})")
    print(vuln_mttr_tbl)
    print("")

def print_help(program):
    print(f"Prints out the historical risk meter vulnerability counts for a year.")
    print(f"{program} <risk meter name> [today]")
    print(f"   <risk meter name> - name of the risk meter")
    print(f"   [today] - if present will only print the vulnerability counts for today")
    print("")

if __name__ == "__main__":
    # Look for the risk meter name.
    if len(sys.argv) > 1:
        risk_meter_name = sys.argv[1]
    else:
        print("Requires risk meter name.")
        print_help(sys.argv[0])
        sys.exit(1)

    # To run this script, please assign your Kenna Risk Token to the KENNA_API_KEY environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)

    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.mttr_vulns/1.0.0 (Cisco Vulnerability Management)'}

    today = date.today()
    month_beginning = today.replace(day=1)
    start_date = month_beginning.replace(year=today.year - 1)
    start_date_str = start_date.isoformat()

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"

    risk_meters = {}
    risk_meters = get_a_risk_meter(base_url, headers, risk_meter_name)
    if risk_meters == {}:
        print(f"{risk_meter_name} not found.")
        sys.exit(1)

    # We want 6 months of data from today, but don't include current month.
    given_date = date.today()
    months_back = 7
    num_months = 6

    # Process the risk meter.
    for risk_meter_name in risk_meters.keys():
        id = risk_meters[risk_meter_name]
        
        process_report(base_url, headers, risk_meter_name, id,
                       given_date, months_back, num_months)
 