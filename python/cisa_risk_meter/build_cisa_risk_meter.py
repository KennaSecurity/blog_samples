import os
import sys
import time
import json
import logging
import requests

VERSION = "1.4.0"

# This might have to changed depending on your setup.
KENNA_BASE_URL = "https://api.kennasecurity.com/"

# Humble constants.
API_MAX_PAGES = 20
CISA_CUSTOM_FIELD_NAME = "CISA"
CISA_RISK_METER_NAME = "CISA Exploited Vulnerabilities"
VULN_UPDATE_LIMIT = 5000

# Maximum page size
SEARCH_PAGE_SIZE = 5000
RISK_METER_PAGE_SIZE = 100

# Dump JSON in a pretty format.  Great for debugging.
def dump_json(json_obj):
    return (json.dumps(json_obj, sort_keys=True, indent=2))

# Process an HTTP error by printing and log.error
def process_http_error(msg, response, url):
    print(f"{msg} HTTP Error: {response.status_code} with {url}")
    if response.text is None:
        logging.error(f"{msg}, {url} status_code: {response.status_code}")
    else:
        logging.error(f"{msg}, {url} status_code: {response.status_code} info: {response.text}")
  
# Print and log warning.
def process_warning(msg):
    print(msg)
    logging.warning(msg)

# Print and log information.
def process_info(msg):
    print(msg)
    logging.info(msg)

# Get the CISA catalog.
def get_cisa_catalog():
    get_cisa_catalog_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    headers = { 'Accept': 'application/json',
                'Content-Type': 'application/json; charset=utf-8' }

    response = requests.get(get_cisa_catalog_url, headers=headers)
    if response.status_code != 200:
        process_http_error("List CISA Catalog API ", response, get_cisa_catalog_url)
        sys.exit(1)

    # Return the CISA catalog.
    return response.json()

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

    # A HTTP error coode 422 is returned when there is no matching custom field,
    # therefore, it is caught here and an empty array is returned.
    if response.status_code == 422:
        print(f"Please configure {custom_field} as a custom field in the UI.")
        process_http_error(f"Search Vulnerabilities API for custom field {custom_field} ", response, search_url)
        logging.error(f"The custom field, {custom_field} needs to be configured in the UI")
        sys.exit(1)

    # Check for other HTTP errors.
    if response.status_code != 200:
        process_http_error(f"Search Vulnerabilities API for custom field {custom_field} ", response, search_url)
        if response.status_code == 401:
           logging.error(f"HTTP header: {dump_json(headers)}")
        sys.exit(1)
    
    resp_json = response.json()
    meta_info = resp_json['meta']
    total_vulns_with_custom_field = meta_info['total_count']
    process_info(f"{total_vulns_with_custom_field} vulnerabilities with {custom_field} custom fields")

    # Return the CISA custom field ID based on the first vulnerability found with CISA custom field.
    vulns = resp_json['vulnerabilities']
    if len(vulns) == 0:
        return 0
    cisa_custom_field = get_custom_field(vulns[0], CISA_CUSTOM_FIELD_NAME)
    return cisa_custom_field['custom_field_definition_id']

# Vulnerabilitity search specified by URL.  Return a tuple of vulnerabilities and metadata.
def search_vulns(search_url, headers):
               
    # Get all the vulnerabilities associated with the CVE via pagination.
    logging.info(f"Vulnerability CVE ID search URL: {search_url}")
    try: 
       response = requests.get(search_url, headers=headers)
    except ConnectionError:
        logging.warn(f"Connection error, waiting three seconds.  URL: {search_url}")
        time.sleep(3)
        response = requests.get(search_url, headers=headers)

    # If too many requests per second, wait 3 seconds.
    if response.status_code == 429:
        logging.warn(f"Too many search requests, waiting three seconds.  URL: {search_url}")
        time.sleep(3)
        response = requests.get(search_url, headers=headers)

    # Check for all other errors.
    if response.status_code != 200:
        process_http_error(f"Search Vulnerabilities API", response, search_url)
        sys.exit(1)
    
    resp_json = response.json()
    return(resp_json['vulnerabilities'], resp_json['meta'])

# CVE ID vulnerability search.
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
    base_search_url = f"{base_url}vulnerabilities/search?{q_str}&per_page={SEARCH_PAGE_SIZE}"

    # Check for the one page case.
    (vulnerabilities, meta_info) = search_vulns(base_search_url, headers)
    if meta_info['page'] == 1:
        return vulnerabilities

    # Multi-page case.  First append vulnerabilitie from page one.
    vulns = []
    vulns.append(vulnerabilities)
    max_pages = meta_info['pages']

    # Loop through available pages colllecting vulnerabilities.
    page_num = 2
    while page_num <= max_pages:
        search_url = f"{base_search_url}&page={page_num}"

        (vulnerabilities, meta_info) = search_vulns(search_url, headers)
        vulns.append(vulnerabilities)
        page_num += 1

    return vulns

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
    if response.status_code != 200:
        process_http_error("Vulnerability Bulk Update API ", response, bulk_update_url)
        sys.exit(1)
    
    resp_json = response.json()
    vulns_updated = resp_json['vulnerabilities_updated']
    if vulns_updated != len(vuln_ids):
        logging.warn("Number of IDs, {len(vuln_ids)} doesn't equal vulns updated, {vulns_updated}.")

    process_info(f"{vulns_updated} vulnerabilities updated with {CISA_CUSTOM_FIELD_NAME} custom field")
    
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
        if response.status_code != 200:
            process_http_error(f"List asset group (risk meter) API", response, list_risk_meters_url)
            sys.exit(1)

        resp_json = response.json()
        
        # Set the maximum number of pages, so that we have one loop.
        if "meta" not in resp_json and "pages" not in resp_json['meta']:
            process_warning(f"'meta' or 'pages' are not in {resp_json} for List Group Assets API. Page={page_num}")
        max_pages = resp_json['meta']['pages']

        if "asset_groups" not in resp_json:
            process_warning(f"'assets_groups' is not in {resp_json} for List Group Assets API. Page={page_num}")
            return None

        risk_meters_resp = resp_json['asset_groups']

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
    if response.status_code != 201:
        process_http_error(f"Create asset group (risk meter) API", response, create_risk_meter_url)
        sys.exit(1)

    process_info(f"Created risk meter: '{risk_meter_name}'")

if __name__ == "__main__":
    logging_file_name = "cisa_vulns.log"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO)
    logging.info("-----------------------------------------------------------")
    process_info(f"Build CISA Exploited Vulnerabilities Risk Meter v{VERSION}")

    cisa_custom_field_id = 0
    if len(sys.argv) > 1:
        cisa_custom_field_id = sys.argv[1]
        logging.info(f"Custom field ID {cisa_custom_field_id} from command line.")

    # Check if the Kenna API key is present and accounted for.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("KENNA_API_KEY environment variable is non-existent.  Please create.")
        logging.error(f"KENNA_API_KEY environment variable is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    user_agent = f"build_cisa_risk_meter/{VERSION} (Kenna Security)"
    headers = {'X-Risk-Token': api_key,
               'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': user_agent }
    
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
    process_info(f"CISA catalog obtained with {cisa_num_vulns} vulnerabilities")

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
        if len(cve_vulns) == 0:
            logging.info(f"All {cisa_cve_id} vulnerabilities have already been marked.")
            continue

        # Check in CISA custom field is assiocated with each vulnerability.
        # If not, add it to the list.
        # If the number of vulnerabilities is over the update limit, do a bulk update.
        for cve_vuln in cve_vulns:
            if not custom_field_is_set(cve_vuln, CISA_CUSTOM_FIELD_NAME):
                cve_vuln_id = cve_vuln['id']
                logging.info(f"Add Vuln ID {cve_vuln_id} to custom field update list")
                vulns_to_update.append(cve_vuln_id)
                if len(vulns_to_update) >= VULN_UPDATE_LIMIT:
                    print("")
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
    
    process_info(f"{CISA_RISK_METER_NAME} created with {vulns_updated} vulnerabilities updated")
