# List Risk Score and True Risks scores.  For each risk meter that the scores
# are not equal, spawn a process to display the vulnerability counts and risk
# accepted vulnerability counts.

import os
import sys
import subprocess
import requests
from prettytable import PrettyTable

# Get risk meter information, and return a dictionary of tuples containing risk meter ID,
# risk meter score, and true risk meter score.
def get_risk_meter_scores(base_url, headers):
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
        #query_string = risk_meter['querystring']
        risk_meter_score = risk_meter['risk_meter_score']
        true_score = risk_meter['true_risk_meter_score']
        risk_meters[risk_meter['name']] = (risk_meter_id, risk_meter_score, true_score)

    return risk_meters

# Obtain and return the number of assets in a risk meter.
if __name__ == "__main__":
    print("")
    print("List Risk Meter Scores")
    print("~~~~~~~~~~~~~~~~~~~~~~")
    print("")

    # Obtain the Kenna Security API key from an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)

    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.list_risk_meter_scores/1.0.0 (Cisco Secure)'}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"

    risk_meters = get_risk_meter_scores(base_url, headers)

    # Initialize the output table.
    risk_meter_tbl = PrettyTable()
    risk_meter_tbl.field_names = ["Risk Meter Name", "ID", "Risk Score", "True Risk Score"]
    risk_meter_tbl.align["Risk Meter Name"] = "l"

    # Go through the list of risk meters filling out the output table.
    for risk_meter_name in sorted (risk_meters.keys()):
        risk_meter_tuple = risk_meters[risk_meter_name]
        risk_meter_id = risk_meter_tuple[0]
        risk_meter_score = risk_meter_tuple[1]
        risk_meter_true_score = risk_meter_tuple[2]
        true_score = f"{risk_meter_true_score}   " if risk_meter_true_score == risk_meter_score else f"{risk_meter_true_score} **"

        risk_meter_tbl.add_row([risk_meter_name, risk_meter_id, risk_meter_score, true_score])

    # Print the output table.
    print(risk_meter_tbl)
    print("")

    print("Vulnerability Counts for Unequal Risk Scores")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("")

    # Go through the risk meters to output risk meter vulnerability counts for unequal scores.
    for risk_meter_name in sorted (risk_meters.keys()):
        risk_meter_tuple = risk_meters[risk_meter_name]
        risk_meter_id = risk_meter_tuple[0]
        risk_meter_score = risk_meter_tuple[1]
        risk_meter_true_score = risk_meter_tuple[2]

        if risk_meter_score != risk_meter_true_score:
            rtn_code = 0
            cmd = ["python",
                   "historical_vuln_count.py",
                   risk_meter_name,
                   "today",
                   str(risk_meter_id),
                   str(risk_meter_score),
                   str(risk_meter_true_score)]
            subprocess.run(cmd)
            subprocess.CompletedProcess(cmd, rtn_code)
            if rtn_code != 0:
                print(f"Error {rtn_code} collecting vulnerability counts for risk meter {risk_meter_name}.")
