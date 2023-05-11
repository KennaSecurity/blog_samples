import os
import sys
import time
import datetime
import logging
import argparse
import json
import yaml
import requests
import validators

VERSION = "1.0.0"

# Constants
NUM_MAX_VULNS = 100000
NUM_MAX_ASSETS = 100000
MAX_ASSET_VULNS = 50000
MAX_URL_LENGTH = 2020  # Max URL length is 2048.  This gives us a little breathing room.

# Singleton class for all the globals.
class GlobalInfo:
    _instance = None

    # Output JSON file with vulnerability information.
    output_json_file_fp = None

    # Search URLs.
    search_assets_url = ""
    base_search_vulns_url = ""
    search_vulns_url = ""

    # Vuln counter.
    num_vulns = 0

    # Asset data.
    num_qs_asset_ids = 0
    asset_vuln_count = 0
    num_assets = 0

    def __new__(cls, json_file_name):
        if cls._instance is None:
            cls._instance = super(GlobalInfo, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, output_json_file_name):
        # Open new JSON file.
        try:
            self.output_json_file_fp = open(output_json_file_name, 'w')
        except Exception as exp:
            print_error(f"File error: {exp}")
            sys.exit(1)

    def close_json_file(self):
        self.output_json_file_fp.close()

    def set_asset_search_url(self, asset_search_url):
        self.search_assets_url = asset_search_url

    def set_vuln_search_url(self, vuln_search_url):
        self.base_search_vulns_url = vuln_search_url
        self.search_vulns_url = self.base_search_vulns_url

    # Appends an asset ID into the array.  Increments asset vuln counter.
    # Determines when to search vulnerabilities for vulnerability information.
    def incr_asset_info(self, asset_id, asset_vuln_count):
        self.search_vulns_url += f"&asset[id][]={asset_id}"
        self.num_qs_asset_ids += 1
        self.asset_vuln_count += asset_vuln_count
        self.num_assets += 1

        if len(self.search_vulns_url) > MAX_URL_LENGTH:
            logging.info(f"Max URL length reached: {len(self.search_vulns_url)} ({self.num_qs_asset_ids})")
            return True
        if self.asset_vuln_count > MAX_ASSET_VULNS:
            logging.info(f"Vuln count limit reached: {self.asset_vuln_count} ({self.num_qs_asset_ids})")
            return True
        
        return False
    
    def reset_asset_info(self):
        self.search_vulns_url = self.base_search_vulns_url
        self.num_qs_asset_ids = 0
        self.asset_vuln_count = 0

    def incr_num_vulns(self):
        self.num_vulns += 1
        return
    
# Obtain the command line arguments.
def get_command_line_options():
                            
    # Create the argument parser with a description.
    arg_parser = argparse.ArgumentParser(description="Show Vulnerability Details via Assets")

    arg_parser.add_argument("-r", "--risk_meter",
                             dest='risk_meter_id',
                             type=int,
                             required=False,
                             default=0,
                             help="Filter assets by the specified risk meter.")

    # Parse and return results.
    args = arg_parser.parse_args()
    return args

# Print and log information.
def print_info(msg):
    print(msg)
    logging.info(msg)

# Print and log warning information.
def print_warning(msg):
    print(msg)
    logging.warning(msg)

# Print and log error information.
def print_error(msg):
    print(msg)
    logging.error(msg)

# Process an HTTP error by printing and log.error
def process_http_error(msg, response, url):
    if response.text is None:
        print_error(f"{msg} HTTP Error: {response.status_code} with {url}")
    else:
        print_error(f"{msg}, {url} status_code: {response.status_code} info: {response.text}")

def get_my_config(config_file):
    config = []

    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
        
    # Check for base_url.
    if "base_url" in config:
        if not validators.url(config['base_url']):
            print_error(f"Invalid base URL: {config['base_url']}")
    else:
        config['base_url'] = "https://api.kennasecurity.com"

    # Check for response fields.
    if not "fields" in config:
        config['fields'] = ""
    
    # Check for output file name.
    if "output_file_name" in config:
        file_parts = os.path.splitext(config['output_file_name'])
        if file_parts[1] != "json":
            print_error("Output file doesn't have a 'json' extension.")
    else:
        config['output_file_name'] = "vuln_info.json"

    print_info(f"Base URL: {config['base_url']},  output file name: {config['output_file_name']}")
    print_info(f"Output fields: {config['fields']}")

    return config

# Forge a log file name for the program name.
def forge_log_file_name(program_file_name):
    prog_file_name_root = os.path.splitext(program_file_name)
    return prog_file_name_root[0] + ".log"

# Forge a an asset serarch URL with page size, and risk meter.
def forge_search_asset_url(base_url, risk_meter_id):
    search_assets_url = f"{base_url}/assets/search"

    query_params = f"?per_page=5000"
    if risk_meter_id > 0:
        query_params += f"&search_id={risk_meter_id}"

    search_assets_url += query_params
    logging.info(f"Search asset URL: {search_assets_url}")
    return search_assets_url

# Forge a vulnerability search URL with page size, and fields.
def forge_search_vuln_url(base_url, fields):
    search_vulns_url = f"{base_url}/vulnerabilities/search"

    # Fields can be modified, or removed.
    if fields != "": 
        fields = "&fields=" + fields
    
    query_params = f"?per_page=5000&" + fields
    search_vulns_url += query_params

    logging.info(f"Search vuln URL: {search_vulns_url}")
    return search_vulns_url

# Performs a search for assets with pre-formed search asset URL.
def search_for_assets(headers, page, global_info:GlobalInfo):

    search_assets_url = global_info.search_assets_url
    query_params = f"&page={page}"
    search_assets_url += query_params

    logging.info(f"Search URL: {search_assets_url}")
    response = requests.get(search_assets_url, headers=headers)
    if response.status_code != 200:
        process_http_error(f"Asset Search API Error", response, search_assets_url)
        sys.exit(1)

    return response.json()

# Processes the assets by colletct asset IDs and counting vulns associated with the asset.
# Once the limit has been reached, vulnerability information is acquired.
def process_assets(assets, global_info:GlobalInfo):
    for asset in assets:
        asset_id = asset['id']
        asset_vuln_count = asset['vulnerabilities_count']

        search_vulns_now = global_info.incr_asset_info(asset_id, asset_vuln_count)
        if search_vulns_now:
            get_vuln_info(headers, global_info)
            global_info.reset_asset_info()

# Performs a search for vulnerabilities with pre-formed search vuln URL.
def search_for_vulns(headers, page, global_info:GlobalInfo):

    # Get the search vuln URL with all the asset IDs.
    search_vulns_url = global_info.search_vulns_url

    query_params = f"&page={page}"
    search_vulns_url += query_params

    logging.info(f"Search URL: {search_vulns_url}")
    response = requests.get(search_vulns_url, headers=headers)

    # If too many requests per second, wait 3 seconds.
    if response.status_code == 429:
        logging.warn(f"Too many vuln search requests, waiting three seconds.  URL: {search_vulns_url}")
        time.sleep(3)
        response = requests.get(search_vulns_url, headers=headers)

    if response.status_code != 200:
        process_http_error(f"Vulnerability Search API Error", response, search_vulns_url)
        sys.exit(1)

    return response.json()

# Process each page of vulnerabilities.
def process_vulns(vulns, global_info:GlobalInfo):
    
    # Go through all the vulnerabilities in this page.
    for vuln in vulns:
        global_info.incr_num_vulns()

        # Dump vuln information to a file in JSON format.
        json.dump(vuln, global_info.output_json_file_fp, indent=2)

    return 
                
# Get the vulns.
def get_vuln_info(headers, global_info:GlobalInfo):
    page = 1
    search_vuln_resp = search_for_vulns(headers, page, global_info)
    search_vulns = search_vuln_resp['vulnerabilities']
    metadata = search_vuln_resp['meta']
    num_pages = metadata['pages']
    total_vuln_count = metadata['total_count']
    print_info(f"Number of vuln pages = {num_pages} with {total_vuln_count:,} vulnerabilities.")

    # Check if all the response vulnerabilities can be processed.
    if total_vuln_count > NUM_MAX_VULNS:
        print_warning(f"There are too many vulnerabilities, {total_vuln_count:,}")
        print(f"Please change the input filters to reduce the number of vulnerabilities to under {NUM_MAX_VULNS:,}.")
        sys.exit(1)

    # Process the first page of vulns.
    process_vulns(search_vulns, global_info)
    print(f"Processed vuln page {page}", end = " ")

    # Maximum number of page is 20.
    if num_pages > 20:
        num_pages = 20
    
    # Obtain and process pages 2 - 20 inclusively.
    for page in range(2, num_pages+1):
        search_vuln_resp = search_for_vulns(headers, page, global_info)
        search_vulns = search_vuln_resp['vulnerabilities']

        process_vulns(search_vulns, global_info)
        print(f"{page}", end = " ")
    print("")

if __name__ == "__main__":
    logging_file_name = forge_log_file_name(sys.argv[0])
    logging_format = "%(asctime)s %(levelname)s %(message)s"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO, format=logging_format)

    print_info(f"Get Scanning Vulnerability Details using Asset IDs v{VERSION}")

    args = get_command_line_options()
    risk_meter_id = args.risk_meter_id

    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print_error(f"Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    user_agent = f"vuln_information_using_assets/{VERSION} (Kenna Security)"
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key,
               'User-Agent': user_agent}

    # Get file based configuration.
    my_config = get_my_config("asset_group_vulns.yml")

    # Create the global info instance with the output JSON file name.
    output_json_file_name = my_config['output_file_name']
    global_info = GlobalInfo(output_json_file_name)

    #-----------------------------------------------------
    # You might have to change the YAML configuration file
    #-----------------------------------------------------
    base_url = my_config['base_url']

    # Set the search URL in the global class instance.
    global_info.set_asset_search_url(forge_search_asset_url(base_url, risk_meter_id))
    global_info.set_vuln_search_url(forge_search_vuln_url(base_url, my_config['fields']))

    # And we're off!
    start_time = time.time()

    # Get all the assets specified by the client.
    page = 1
    search_asset_resp = search_for_assets(headers, page, global_info)
    search_assets = search_asset_resp['assets']
    metadata = search_asset_resp['meta']
    num_pages = metadata['pages']
    total_asset_count = metadata['total_count']
    print_info(f"Number of asset pages = {num_pages} with {total_asset_count:,} assets.")

    # Check if all the response assets can be processed.
    if total_asset_count > NUM_MAX_ASSETS:
        print_warning(f"There are too many assets, {total_asset_count:,}")
        print(f"Please change the input filters to reduce the number of assets to under {NUM_MAX_ASSETS:,}.")
        sys.exit(1)

    process_assets(search_assets, global_info)

    if num_pages > 20:
        num_pages = 20

    # Interate over available pages.
    for page in range(2, num_pages+1):
        search_asset_resp = search_for_assets(headers, page, global_info)
        search_assets = search_asset_resp['assets']

        process_assets(search_assets, global_info)

    end_time = time.time()
    time_diff_str = str(datetime.timedelta(seconds=(end_time - start_time)))
    print_info(f"Obtaining vuln details took {time_diff_str}.")

    global_info.close_json_file()

    print_info(f"Vulns: {global_info.num_vulns:,}")
    print_info(f"Assets: {global_info.num_assets:,}")
