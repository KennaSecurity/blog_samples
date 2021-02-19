# Lists the assets' ID, hostname and note for active and inactive assets.
# Displays the first 500 assets, because there is no pagination code.

import os
import sys
import requests

status_opt = "both"

if len(sys.argv) > 1:
    opt = sys.argv[1]
    if (opt == "active") or (opt == "inactive"):
        status_opt = opt
    else:
        print(sys.argv[0] + " [active | inactive]")
        print("If option not specified that both active and inactive stati are displayed.")
        sys.exit(1)

print("List Assets")

# API_KEY is an environment variable.
api_key = os.getenv('API_KEY')
if api_key is None:
    print("API key is non-existent")
    sys.exit(1)

# HTTP header.
headers = {'Accept': 'application/json',
           'X-Risk-Token': api_key}

def sortFunc(entry):
    return entry['id']

# List assests depending on the URL. Context is displayed.
def list_assets(url, context):
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print("List Asset Error: " + str(response.status_code))
        sys.exit(1)

    resp_json = response.json()
    #print(resp_json)

    assets = resp_json['assets']

    print(context)

    # Run through all the assets and print asset ID, asset hostname, and asset note.
    assets.sort(key=sortFunc)
    for asset in assets:
        if asset['id'] is None:
            continue

        hostname = "no hostname" if asset['hostname'] is None else asset['hostname']
        notes = "" if asset['notes'] is None or asset['notes'] == "" else " : " + asset['notes']

        out_buf = str(asset['id']) + " : " + asset['status'] + " ; " + hostname + notes
        print(out_buf)

    print("Number of " + context + ": " + str(len(assets)))

# List active assets.
list_active_assets_url = "https://api.kennasecurity.com/assets"
if (status_opt == "both") or (status_opt == "active"):
    list_assets(list_active_assets_url, "Active Assets")

    print("")

# List inactive assets.
if (status_opt == "both") or (status_opt == "inactive"):
    list_inactive_assets_url = list_active_assets_url + "?filter=inactive"
    list_assets(list_inactive_assets_url, "Inactive Assets")
