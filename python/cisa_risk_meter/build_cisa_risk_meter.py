import os
import sys
import time
import json
import logging
import requests

# Humble constants.
API_MAX_PAGES = 20
CISA_CUSTOM_FIELD_NAME = "CISA"
CISA_RISK_METER_NAME = "CISA Exploited Vulnerabilities"
VULN_UPDATE_LIMIT = 5000

# Maximum page size
SEARCH_PAGE_SIZE = 5000
RISK_METER_PAGE_SIZE = 100

# This might have to changed depending on your setup.
KENNA_BASE_URL = "https://api.kennasecurity.com/"

# Dump JSON in a pretty format.  Great for debugging.
def print_json(json_obj):
    print(json.dumps(json_obj, sort_keys=True, indent=2))

# Get the CISA catalog.
def get_cisa_catalog():
    get_cisa_catalog_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    headers = { 'Accept': 'application/json',
                'Content-Type': 'application/json; charset=utf-8' }

    response = requests.get(get_cisa_catalog_url, headers=headers)
    if response.status_code != 200:
        print(f"List CISA Catalog Error: {response.status_code} with {get_cisa_catalog_url}")
        logging.error(f"List CISA Catalog API, {get_cisa_catalog_url} error: {resp_json}")
        sys.exit(1)

    resp_json = response.json()

    # Return the CISA catalog.
    return resp_json

# Checks for a custom_field name is associated with the vulnerability.
# Returns the custom field or None.
def get_custom_field(vuln, custom_field_name):
    custom_fields = vuln['custom_fields']

    for custom_field in custom_fields:
        if custom_field['name'] == custom_field_name:
            return custom_field

    return None

# Checks if the custom field is set, meaning it has the string value "true".
def custom_field_is_set(vuln, custom_field_name):
    custom_field = get_custom_field(vuln, custom_field_name)
    if custom_field is None:
        return False

    if custom_field['value'] == "true":
        return True
    
    return False

# Check for the custom field.  This is really a search vulnernabilities with a custom field.
# Return the custom field ID.
def check_for_custom_field(base_url, headers, custom_field):

    # Assemble the search URL.
    page_size_query = f"per_page={SEARCH_PAGE_SIZE}"
    custom_field_query = f"custom_fields:{custom_field}[]=none"
    search_url = f"{base_url}vulnerabilities/search?{page_size_query}&{custom_field_query}"
    logging.info(f"Vulnerability custom field search URL: {search_url}")
               
    response = requests.get(search_url, headers=headers)
    resp_json = response.json()

    # A HTTP error coode 422 is returned when there is no matching custom field,
    # therefore, it is caught here and an empty array is returned.
    if response.status_code == 422:
        print(f"Please configure {custom_field} as a custom field in the UI.")
        logging.error(f"Search Vulnerabilities for custom field {custom_field} API, {search_url}, error: {resp_json}")
        logging.error(f"The custom field, {custom_field} needs to be configured in the UI")
        sys.exit(1)

    # Check for other HTTP errors.
    if response.status_code != 200:
        print(f"Search Vulns Error: {response.status_code} with {search_url}")
        logging.error(f"Search Vulnerabilities for custom field {custom_field} API, {search_url}, error: {resp_json}")
        print_json(resp_json)
        sys.exit(1)
    
    meta_info = resp_json['meta']
    total_vulns_with_custom_field = meta_info['total_count']
    print(f"{total_vulns_with_custom_field} vulnerabilities with {custom_field} custom field.")
    logging.info(f"{total_vulns_with_custom_field} vulnerabilities with {custom_field} custom fields")

    # Return the CISA custom field ID based on the first vulnerability found with CISA custom field.
    vulns = resp_json['vulnerabilities']
    if len(vulns) == 0:
        return 0
    cisa_custom_field = get_custom_field(vulns[0], CISA_CUSTOM_FIELD_NAME)
    return cisa_custom_field['custom_field_definition_id']

# CVE ID search.
def search_vulns_for_cve_id(base_url, headers, cve_id):
    logging.info(f"Searching vulnerabilities for CVE ID {cve_id}")

    # Make a searchable CVE ID.
    cve_str = cve_id[0:4].upper()
    if cve_str != "CVE-":
        print(f"Input is not a CVE, {cve_str}")
        logging.error(f"Internal error: Expecting CVE, but it was {cve_str}")
        sys.exit(1)

    cve_id_str = cve_id[4:]
    
    # Assemble the Search Vulnerability URL.
    q_str = f"q=cve:{cve_id_str}"
    search_url = f"{base_url}vulnerabilities/search?{q_str}"
    logging.info(f"Vulnerability CVE ID search URL: {search_url}")
               
    try: 
       response = requests.get(search_url, headers=headers)
    except ConnectionError:
        logging.warn(f"Connection error, waiting three seconds.  URL: {search_url}")
        time.sleep(3)
        response = requests.get(search_url, headers=headers)
    resp_json = response.json()

    # If too many requests per second, wait a second.
    if response.status_code == 429:
        logging.warn(f"Too many search requests, waiting three seconds.  URL: {search_url}")
        time.sleep(3)
        response = requests.get(search_url, headers=headers)
        resp_json = response.json()

    # Check for all other errors.
    if response.status_code != 200:
        print(f"Search Vulns Error: {response.status_code} with {search_url}")
        print_json(resp_json)
        logging.error(f"Search Vulnerabilities with query string {q_str} API, {search_url}, error: {resp_json}")
        sys.exit(1)
    
    return resp_json['vulnerabilities']

def update_cisa_vulns(base_url, headers, vuln_ids, custom_field_id):
    if len(vuln_ids) == 0:
        return

    bulk_update_url = f"{base_url}vulnerabilities/bulk"
    update_custom_field_id = f"{custom_field_id}"
    update_data = {
        "vulnerability_ids": vuln_ids,
        "vulnerability": {
            "custom_fields": {
                update_custom_field_id: "true"
            }
        }
    }

    response = requests.put(bulk_update_url, headers=headers, data=json.dumps(update_data))
    resp_json = response.json()
    if response.status_code != 200:
        print(f"List CISA Catalog Error: {response.status_code} with {bulk_update_url}")
        logging.error(f"Vulnerability bulk update API, {bulk_update_url}, error: {resp_json}")
        sys.exit(1)
    
    logging.info(f"{len(vuln_ids)} vulnerabilities updated with {CISA_CUSTOM_FIELD_NAME} custom field")
    
# Get a risk meter (asset group) by name.
def get_a_risk_meter(base_url, headers, risk_meter_name):
    max_pages = API_MAX_PAGES
    page_num = 1
    while page_num <= max_pages:
        page_size_query = f"per_page={RISK_METER_PAGE_SIZE}"
        list_risk_meters_url = f"{base_url}asset_groups?{page_size_query}&page={page_num}"
        logging.info(f"List risk meter URL: {list_risk_meters_url}")

        # Invoke the List Asset Groups (Risk Meters) API.
        response = requests.get(list_risk_meters_url, headers=headers)
        resp_json = response.json()
        if response.status_code != 200:
            print(f"List Risk Meters Error: {response.status_code} with {list_risk_meters_url}")
            logging.error(f"List asset group (risk meter) API, {list_risk_meters_url} error: {resp_json}")
            sys.exit(1)

        risk_meters_resp = resp_json['asset_groups']
        # Set the maximum number of pages, so that we have one loop.
        max_pages = resp_json['meta']['pages']

        # Search for the risk meter by name.
        for risk_meter in risk_meters_resp:
            if risk_meter['name'] == risk_meter_name:
                logging.info(f"Risk meter {risk_meter_name} exists.")
                return risk_meter

        page_num += 1
        
    logging.info(f"Risk meter '{risk_meter_name}' not found.")
    return None

# Create a risk meter (asset groug), with a CISA custom field query string.
# Both the custom field name and custom field ID are required.
def create_risk_meter(base_url, headers, risk_meter_name, cisa_custom_field_id):
    create_risk_meter_url = f"{base_url}asset_groups"
    vuln_custom_fields = f"custom_fields:{cisa_custom_field_id}:{CISA_CUSTOM_FIELD_NAME}"
    create_data = {
        "name": risk_meter_name,
        "query": {
            "status": [
                "active"
            ],
            "vulnerability": {
                vuln_custom_fields: [
                    "any"
                ],
                "status": [
                    "open"
                ]
            }
        }
    }

    # Invoke the Create Asset Groups (Risk Meters) API.
    response = requests.post(create_risk_meter_url, headers=headers, data=json.dumps(create_data))
    resp_json = response.json()
    if response.status_code != 201:
        print(f"Create Risk Meters Error: {response.status_code} with {create_risk_meter_url}")
        logging.error(f"Create asset group (risk meter) API, {create_risk_meter_url} error: {resp_json}")
        sys.exit(1)

    print(f"Created risk meter: '{risk_meter_name}'.")
    logging.info(f"Created risk meter: '{risk_meter_name}'")

if __name__ == "__main__":
    print("Build CISA Exploited Vulnerabilities Risk Meter\n")

    logging_file_name = "cisa_vulns.log"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO)
    logging.info("Build CISA Exploited Vulnerabilities Risk Meter")

    cisa_custom_field_id = 0
    if len(sys.argv) > 1:
        cisa_custom_field_id = sys.argv[1]
        logging.info(f"Custom field ID {cisa_custom_field_id} from command line.")

    # Check if the Kenna API key is present and accounted for.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("KENNA API key is non-existent")
        logging.error(f"KENNA API KEY environment variable is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'build_cisa_risk_meter/1.0.0 (Kenna Security)'}
    
    # Kenna Base URL for all Kenna API endpoints.
    base_url = KENNA_BASE_URL

    # If CISA custom field ID was not passed via the command line, let's see if we can find the
    # CISA custom field associated with vulnerabilities.
    if cisa_custom_field_id == 0:
        cisa_custom_field_id = check_for_custom_field(base_url, headers, CISA_CUSTOM_FIELD_NAME)
        logging.info(f"Found {cisa_custom_field_id} custom field ID from vulnerabilites.")

    # Obtain the CISA catalog.
    cisa_catalog = get_cisa_catalog()

    # Extract CISA catalog information.
    cisa_title = cisa_catalog['title']
    cisa_date_released = cisa_catalog['dateReleased']
    cisa_num_vulns = cisa_catalog['count']
    cisa_vulns = cisa_catalog['vulnerabilities']
    if cisa_num_vulns != len(cisa_vulns):
        print(f"Count of {cisa_num_vulns} does equal vuln array length {len(cisa_vulns)}")
        logging.error(f"CISA API internal error: Count of {cisa_num_vulns} does equal vuln array length {len(cisa_vulns)}")
        sys.exit(1)
    logging.info(f"CISA catalog obtained with {cisa_num_vulns} vulnerabilities")

    # Before we start searching for CISA vulnerabilities, let's see if we have a CISA risk meter.
    # Let's make it easy and search by name.  (We could search by query string.)
    cisa_risk_meter = get_a_risk_meter(base_url, headers, CISA_RISK_METER_NAME)
    if cisa_risk_meter is None:
        # Create a risk meter.
        if cisa_custom_field_id == 0:
            print("To create a CISA risk meter, the custom field ID of the CISA custom field ")
            print("is required as an input parameter.")
            print(f"{sys.argv[0]} <custom field_id>")
            print("")
            print("Please obtain the CISA custom field ID from the UI.")
            logging.error(f"User input error.")
            sys.exit(1)

        create_risk_meter(base_url, headers, CISA_RISK_METER_NAME, cisa_custom_field_id)

    # Keep a list of vulnerabilities for custom field updates.
    vulns_to_update = []
    vulns_updated = 0

    # Find vulns by CVE ID on the CISA list.
    # Assume CISA vulnerabilites are NOT removed from the list.
    print(f"Search vulnerabilities associated with CISA CVE IDs")
    for cisa_vuln in cisa_vulns:
        cisa_cve_id = cisa_vuln['cveID']
        
        # Search for vulns associated with the CVE ID.
        cve_vulns = search_vulns_for_cve_id(base_url, headers, cisa_cve_id)
        print(".",  end='', flush=True)

        # Check in CISA custom field is assiocated with each vulnerability.
        # If not, add it to the list.
        # If the number of vulnerabilities is over the update limit, do a bulk update.
        for cve_vuln in cve_vulns:
            if not custom_field_is_set(cve_vuln, CISA_CUSTOM_FIELD_NAME):
                cve_vuln_id = cve_vuln['id']
                logging.info(f"Add Vuln ID {cve_vuln_id} to custom field update list")
                vulns_to_update.append(cve_vuln_id)
                if len(vulns_to_update) > VULN_UPDATE_LIMIT:
                    update_cisa_vulns(base_url, headers, vulns_to_update, cisa_custom_field_id)
                    logging.info(f"Updated CISA custom field for {len(vulns_to_update)} vulns")
                    vulns_updated += len(vulns_to_update)
                    vulns_to_update.clear()

    print("")
    # Bulk vulnerability update of CISA custom fields.
    if len(vulns_to_update) > 0:
        update_cisa_vulns(base_url, headers, vulns_to_update, cisa_custom_field_id)
        logging.info(f"Final updated CISA custom field for {len(vulns_to_update)} vulns")
        vulns_updated += len(vulns_to_update)
    
    print(f"{CISA_RISK_METER_NAME} created with {vulns_updated} vulnerabilities updated.")
    logging.info(f"{CISA_RISK_METER_NAME} created with {vulns_updated} vulnerabilities updated")
