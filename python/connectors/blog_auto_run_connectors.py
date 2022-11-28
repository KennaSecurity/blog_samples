# Checks if connector will be launched based on the number of interval hours between the
# last run and now.

import json
import os
import sys
from datetime import datetime, timedelta
import requests
from prettytable import PrettyTable

def print_help(prog_name):
    print("Automate connector runs.  Options:")
    print(f"   {prog_name} <hours since last run>")
    print(f"   {prog_name} <hours since last run> -f")
    print(f"   {prog_name} -f")
    print("")
    print(f"   <hours since last run> is an integer.")
    print(f"   -f force a run if the connector was never ran.")
    print("")
    sys.exit(1)

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

# Gets the connector runs for the specified connector ID.
def get_connector_runs(base_url, headers, connector_id):
    get_connector_runs_url = f"{base_url}connectors/{connector_id}/connector_runs"

    response = requests.get(get_connector_runs_url, headers=headers)
    if response.status_code != 200:
        print(f"List Connector Runs Error: {response.status_code} with {get_connector_runs_url}")
        sys.exit(1)
    
    resp_json = response.json()
    
    return resp_json

# Forge a file name from the connector name, and verify it is a file.
def forge_and_verify_file_name(file_name):
    file_ok = False

    file_name = file_name.replace(" ", "_") + ".json"
    file_name = os.path.abspath(file_name)
    if os.path.isfile(file_name):
        file_ok = True

    return (file_ok, file_name)

# Upload a file and run the connector.
def upload_and_run_file_connector(base_url, headers, connector_id, connector_name, upload_file_name):
    upload_file_url = f"{base_url}connectors/{connector_id}/data_file"
    
    # Remove Content-Type or it won't work.
    upload_headers = headers
    upload_headers.pop("Content-Type")

    try:
        upload_f = open(upload_file_name, 'rb')
    except FileNotFoundError:
        print(f"File {upload_file_name} should exist!")
        sys.exit(1)
    
    files = {
        'file': (upload_file_name, upload_f, 'application/json')
    }

    payload = {
        'run': True
    }

    response = requests.post(upload_file_url, headers=upload_headers, data=payload, files=files)
    if response.status_code != 200:
        print(f"Upload File Connector Error: {response.status_code} for {connector_name} with {upload_file_url}")
        sys.exit(1)
    
    resp_json = response.json()
    if not resp_json['success']:
        print(f"Uploading {upload_file_name} for {connector_name} ({connector_id}) failed.  Check log files.")
        sys.exit(1)
    
    return resp_json['connector_run_id']

# Starts a connector run based on the connector ID and returns a connector run ID.
def run_connector(base_url, headers, connector_id, connector_name):
    run_connector_url = f"{base_url}connectors/{connector_id}/run"

    response = requests.get(run_connector_url, headers=headers)
    if response.status_code != 200:
        print(f"Run Connector Error: {response.status_code} for {connector_name} with {run_connector_url}")
        print(f"More Info:\n {response.text}")
        sys.exit(1)
    
    resp_json = response.json()
    if not resp_json['success']:
        print(f"Running {connector_name} ({connector_id}) failed.  Check log files.")
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
    force = False

    if len(sys.argv) > 2:
        if sys.argv[2] == "-f":
            force = True
        else:
            print(f"{sys.argv[2]} is not a correct option.")
            print_help(sys.argv[0])

    if len(sys.argv) > 1:
        if sys.argv[1] == "-f":
            force = True
        else:
            try:
                interval_hours = int(sys.argv[1])
            except ValueError:
                print(f"{sys.argv[1]} is not a valid integer.")
                print_help(sys.argv[0])
    
            if interval_hours < MIN_INTERVAL_HOURS:
                print(f"{interval_hours} is less than the mininal number of hours. ({MIN_INTERVAL_HOURS})")
                print_help(sys.argv[0])
            
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
               'Accept': 'application/json; charset=utf-8',
               'User-Agent': 'automate_connector_run/2.0.0 (Kenna Security)'}
    
    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    # Obtain the initial list of connectors.
    connectors = get_connectors(base_url, headers)

    # Set up the output table
    conn_tbl = PrettyTable()
    conn_tbl.field_names = ["Connector Name", "Status"]
    conn_tbl.align["Connector Name"] = "l"
    conn_tbl.align["Status"] = "l"
    conn_tbl.border = False
    conn_tbl.add_row(["~~~~~~~~~~~~~~", "~~~~~~"])

    # Go through the list of connectors to see if any connector is ready to launch.
    for connector in connectors:
        id = connector['id']
        name = connector['name']

        # Obtain the connector runs for a connector.
        connector_runs = get_connector_runs(base_url, headers, id)
        if len(connector_runs) == 0:
            conn_tbl.add_row([name, "has no connector runs"])
            continue

        # Only check the latest run
        latest_run = connector_runs[0] 
        start_datetime = parse_time_str(latest_run['start_time'])
        end_datetime = parse_time_str(latest_run['end_time'])
 
        if latest_run['end_time'] is None:
            conn_tbl.add_row([name, "still running"])
            continue 

        # Check if the end time was interval hours ago.
        if (end_datetime + timedelta(hours=interval_hours)) > datetime.now():
            conn_tbl.add_row([name, f"has to wait {interval_hours} hours past {end_datetime}."])
            continue

        # Check if connector is file based.
        if connector['host'] is None:
            (file_ok, upload_file_name) = forge_and_verify_file_name(name)
            if not file_ok:
                conn_tbl.add_row([name, f"file based connector expecting {upload_file_name}"])
                continue

            # Run the connector if the file is younger the last connection run.
            file_mod_time = os.path.getmtime(upload_file_name)
            file_mod_datetime = datetime.fromtimestamp(file_mod_time)
            if file_mod_datetime > end_datetime:
                connector_run_id = upload_and_run_file_connector(base_url, headers, id, name, upload_file_name)
                conn_tbl.add_row([name, f"{upload_file_name} uploaded, and launched connector run {connector_run_id}."])
                continue
            else:
                conn_tbl.add_row([name, f"{upload_file_name} has not been modified since last connector run"])
                continue
                
        else:
            # Launch the connector if all tests passed.
            connector_run_id = run_connector(base_url, headers, id, name)
            conn_tbl.add_row([name, f"launched connector run {connector_run_id}."])
            continue

    # Print the results in a table form.
    print(conn_tbl)
    print("")
