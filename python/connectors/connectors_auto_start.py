# Checks if connector will be launched  based on the number of interval hours between the
# last run and now.

import os
import sys
import json
import requests
from datetime import datetime, timedelta
from prettytable import PrettyTable

# Returns connector information from the List Connectors API.
def get_connectors(base_url, headers):
    connectors = []
    list_connectors_url = f"{base_url}connectors"

    response = requests.get(list_connectors_url, headers=headers)
    if response.status_code != 200:
        print(f"List Connector Error: {response.status_code} with {list_connectors_url}")
        sys.exit(1)
    
    resp_json = response.json()
    connectors = resp_json['connectors']

    return connectors

# Gets the connector runs for a the specified connector ID.
def get_connector_runs(base_url, headers, connector_id):
    get_connector_runs_url = f"{base_url}connectors/{connector_id}/connector_runs"

    response = requests.get(get_connector_runs_url, headers=headers)
    if response.status_code != 200:
        print(f"List Connector Runs Error: {response.status_code} with {get_connector_runs_url}")
        sys.exit(1)
    
    resp_json = response.json()
    
    return resp_json

# Starts a connector run based on the connector ID and returns a connector run ID.
def run_connector(base_url, headers, connector_id):
    run_connector_url = f"{base_url}connectors/{connector_id}/run"

    response = requests.get(run_connector_url, headers=headers)
    if response.status_code != 200:
        print(f"Run Connector Error: {response.status_code} with {run_connector_url}")
        sys.exit(1)
    
    resp_json = response.json()
    if not resp_json['success']:
        print(f"Running {connector_id} failed.  Check log files.")
        sys.exit(1)

    return resp_json['connector_run_id']

# Parses Kenna time string format.
def parse_time_str(time_str):
    return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")

if __name__ == "__main__":
    # Set the default interval hours between a connector run finishing and the
    # launch of a connector run.
    interval_hours = 24
    MIN_INTERVAL_HOURS = 5

    if len(sys.argv) > 1:
        try:
            interval_hours = int(sys.argv[1])
        except ValueError:
            print(f"{sys.argv[1]} is not a valid integer.")
            sys.exit(1)

        if interval_hours < MIN_INTERVAL_HOURS:
            print(f"{interval_hours} is less than the mininal number of hours. ({MIN_INTERVAL_HOURS})")
            sys.exit(1)
            
    print("Connector Auto Start")
    print("")

    # Obtain the Kenna Security API key from an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)
    
    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.connector_ui/1.0.0 (Cisco Secure)'}
    
    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    # Obtain the initial list of connectors.
    connectors = get_connectors(base_url, headers)

    # Set up the output table
    conn_tbl = PrettyTable()
    conn_tbl.field_names = ["Connector Name", "Status"]
    conn_tbl.align["Connector Name"] = "r"
    conn_tbl.align["Status"] = "l"
    conn_tbl.border = False
    conn_tbl.add_row(["~~~~~~~~~~~~~~", "~~~~~~"])

    # Go through the list of connectors to see if any connector is ready to launch.
    for connector in connectors:
        id = connector['id']
        name = connector['name']

        if connector['host'] is None:
            conn_tbl.add_row([name, "is a file connector"])
            continue    

        # Obtain the connector runs for a a connector.
        connector_runs = get_connector_runs(base_url, headers, id)
        if len(connector_runs) == 0:
            conn_tbl.add_row([name, "has no runs"])
            continue

        # Only check the latest run
        latest_run = connector_runs[0] 
        start_datetime = parse_time_str(latest_run['start_time'])
        if latest_run['end_time'] is None:
            conn_tbl.add_row([name, "still running"])
            continue 
        end_datetime = parse_time_str(latest_run['end_time'])
 
        # Check if the end time was interval hours ago.
        if (end_datetime + timedelta(hours=interval_hours)) > datetime.now():
            conn_tbl.add_row([name, f"has to wait {interval_hours} hours past {end_datetime}."])
            continue

        # Launch the connector if all tests passed.
        connector_run_id = run_connector(base_url, headers, id)    
        conn_tbl.add_row([name, f"launched connector run {connector_run_id}."])

    # Print the results in a table form.
    print(conn_tbl)
    print("")
