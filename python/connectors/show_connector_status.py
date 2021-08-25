# Checks if connector will run based on the number of interval hours between the
# last run and now.

import os
import sys
import json
import requests
from datetime import datetime, timedelta

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
def get_connector_runs(base_url, headers, connector_id):
    connector_runs = []
    get_connector_runs_url = base_url + "connectors/" + str(connector_id) + "/connector_runs"

    response = requests.get(get_connector_runs_url, headers=headers)
    if response.status_code != 200:
        print(f"List Connector Runs Error: {response.status_code} with {get_connector_runs_url}")
        sys.exit(1)
    
    resp_json = response.json()
    
    return resp_json

def list_connectors(connectors):
    print("")
    pad = 1 if len(connectors) < 9 else 2
    conn_pad = " " * (pad+2)
    print(f"{conn_pad}Connector Name")
    print(f"{conn_pad}~~~~~~~~~~~~~~")

    i = 1
    for connector in connectors:
        if connector['running']:
            print(f"{i:{pad}}: {connector['name']}\t running")
        else:
            print(f"{i:{pad}}: {connector['name']}")
        i += 1

    print("")

def dump_connector_run(connector_run):
    print(json.dumps(connector_runs, sort_keys=True, indent=2))
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
    
    # Obtain the initial list of connectors and their state.
    connectors = get_connectors(base_url, headers)
    list_connectors(connectors)

    for connector in connectors:
        id = connector['id']
        name = connector['name']

        if connector['host'] == None:
            print(f"{name} is a file connector.")
            continue    

        connector_runs = get_connector_runs(base_url, headers, id)
        if len(connector_runs) == 0:
            print(f"{name} has no runs.")
            continue

        first_run = connector_runs[0] 
        start_datetime = parse_time_str(first_run['start_time'])
        if first_run['end_time'] is None:
            print(f"{name} still running. (end time null)")
            continue 
        end_datetime = parse_time_str(first_run['end_time'])
 
        if end_datetime < start_datetime:
            print(f"{name} still running.")
            continue  # Still running

        if (end_datetime + timedelta(hours=interval_hours)) > datetime.now():
            print(f"{name} has to wait {interval_hours} hours past {end_datetime}.")
            continue  # Not interval hours yet

        print(f"Time to launch {name}.")
