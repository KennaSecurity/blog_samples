# Checks if onnector will run based on the number of interval hours between the
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
    list_connectors_url = base_url + "connectors"

    response = requests.get(list_connectors_url, headers=headers)
    if response.status_code != 200:
        print(f"List Connector Error: {response.status_code} with {list_connectors_url}")
        sys.exit(1)
    
    resp_json = response.json()
    connectors = resp_json['connectors']

    return connectors

# Gets the connector runs for the specified connector ID.
def get_connector_runs(base_url, headers, connector_id, connector_name):
    connector_runs = []
    get_connector_runs_url = base_url + "connectors/" + str(connector_id) + "/connector_runs"

    response = requests.get(get_connector_runs_url, headers=headers)
    if response.status_code != 200:
        print(f"List Connector Runs Error: {response.status_code} for {connector_name} with {get_connector_runs_url}")
        print(f"More Info:\n {response.text}")
        sys.exit(1)
    
    resp_json = response.json()
    
    return resp_json

def dump_connector_run(connector_run):
    print(json.dumps(connector_run, sort_keys=True, indent=2))
    print("")

def dump_connector_runs(connector_runs):
    if len(connector_runs) == 0:
        return

    print(json.dumps(connector_runs, sort_keys=True, indent=2))
    print("")

# Parses Kenna time string format.
def parse_time_str(time_str):
    return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")

if __name__ == "__main__":
    # Set the default interval hours between a connector run finishing and the
    # launch of a connector run.
    interval_hours = 24

    if len(sys.argv) > 1:
        try:
            interval_hours = int(sys.argv[1])
        except ValueError:
            print(f"{sys.argv[1]} is not a valid integer.")
            sys.exit(1)

    print("List Connector Runs")

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
    
    # Obtain the initial list of connectors and their state.
    connectors = get_connectors(base_url, headers)
    print(f"Gathering connection run information for {len(connectors)} connectors.")
    print("")

    # Initialize the table.
    conn_tbl = PrettyTable()
    conn_tbl.field_names = ["ID", "Connector Name", "Status", "Substatus"]
    conn_tbl.align["ID"] = "l"
    conn_tbl.align["Connector Name"] = "l"
    conn_tbl.align["Status"] = "l"
    conn_tbl.align["Substatus"] = "l"
    conn_tbl.border = False
    conn_tbl.add_row(["~~", "~~~~~~~~~~~~~~", "~~~~~~", "~~~~~~~~~"])

    for connector in connectors:
        id = connector['id']
        name = connector['name']
        row = []
        row.append(id)
        row.append(name)

        file_connector = ""
        if connector['host'] == None:
            file_connector = "(file)"

        if connector['running']:
            row.append(f"running {file_connector}") 
        else:
            row.append(f"idle {file_connector}") 

        connector_runs = get_connector_runs(base_url, headers, id, name)
        if len(connector_runs) == 0:
            row.append("has no runs")
            conn_tbl.add_row(row)
            continue

        first_run = connector_runs[0] 
        run_id = first_run['id']

        if first_run['start_time'] is None:
            row.append(f"{run_id}")
            conn_tbl.add_row(row)
            continue 

        start_datetime = parse_time_str(first_run['start_time'])
        if first_run['end_time'] is None:
            row.append(f"{run_id}: still running")
            conn_tbl.add_row(row)
            continue 
        end_datetime = parse_time_str(first_run['end_time'])
 
        if end_datetime < start_datetime:
            row.append(f"{run_id}: still running")
            conn_tbl.add_row(row)
            continue  # Still running

        if (end_datetime + timedelta(hours=interval_hours)) > datetime.now():
            row.append(f"{run_id}: has to wait {interval_hours} hours past {end_datetime}")
            conn_tbl.add_row(row)
            continue  # Not interval hours yet

        row.append(f"{run_id}: Time to launch")
        conn_tbl.add_row(row)

    print(conn_tbl)

