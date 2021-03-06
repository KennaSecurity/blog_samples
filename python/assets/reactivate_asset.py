# Sets the remove override to true.  This will reset any asset's status
# manual override.
# A note can be added.  If note is not present it the note is set to an empty string.

import os
import sys
import json
import requests

str_asset_id = sys.argv[1]
print(f"Set Asset Remove Override on {str_asset_id}")

if len(sys.argv) <= 1:
    print("Asset ID parameter required")
    print(sys.argv[0] + "<asset_id> [note]")
    sys.exit(1)

# If there a note, collect it.
note = ""
if len(sys.argv) > 2:
    note = sys.argv[2]

# KENNA_API_KEY is an environment variable.
api_key = os.getenv('KENNA_API_KEY')
if api_key is None:
    print("Environment variable KENNA_API_KEY is non-existent")
    sys.exit(1)

# HTTP header.
headers = {'Content-Type': 'application/json; charset=utf-8',
           'X-Risk-Token': api_key}

# Forge the update asset URL by adding the asset ID.
url = "https://api.kennasecurity.com/assets"
update_asset_url = url + "/" + str_asset_id

# This will reset notes if notes is not specified.
asset_info = {
    'asset': {
        'remove_override': True,
        'notes' : note
    }
}

# main
# Invoke the update asset API.
try:
    response = requests.put(update_asset_url, headers=headers, data=json.dumps(asset_info))
except Exception as exp:
    print("Set Asset Remote Override Error: " + exp.__str__())
    sys.exit(1)

# Check for HTTP status.
if response.status_code != 204:
    print("Set Asset Remote Override Error: " + str(response.status_code))
    print("Message: " + response.json()['message'])
    sys.exit(1)

print("Asset ID " + str_asset_id + " override removed.")
