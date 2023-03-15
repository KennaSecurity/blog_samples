import os
import sys
import logging
import requests

# Counts the number of closed vulnerabilities for the last 7 days.

VERSION = "1.0.0"

# Print and log information.
def print_info(msg):
    print(msg)
    logging.info(msg)

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

# Forge a log file name for the program name.
def forge_log_file_name(program_file_name):
    prog_file_name_root = os.path.splitext(program_file_name)
    return prog_file_name_root[0] + ".log"

# Performs a vulnerabilities search with the status of closed for the last seven days.
def search_closed_vulns(base_url, headers):
    search_vulns_url = f"{base_url}/vulnerabilities/search"

    # See https://help.kennasecurity.com/hc/en-us/articles/206280593-Kenna-Search-Terms for q search terms.
    query_params = "?status[]=closed&q=closed_at:>now-7d&fields=id,created_at,last_seen_time,cve_id,description"
    search_vulns_url += query_params

    response = requests.get(search_vulns_url, headers=headers)
    if response.status_code != 200:
        process_http_error(f"Vulnerability Search API Error", response, search_vulns_url)
        sys.exit(1)

    return response.json()

if __name__ == "__main__":
    logging_file_name = forge_log_file_name(sys.argv[0])
    logging_format = "%(asctime)s %(levelname)s %(message)s"
    logging.basicConfig(filename=logging_file_name, level=logging.INFO, format=logging_format)
    print_info(f"Search for Closed Vulnerabilities in the Last Week v{VERSION}")

    # Obtain the Kenna Security API key.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print_error(f"Environment variable KENNA_API_KEY is non-existent")
        sys.exit(1)
    
    # HTTP headers for Kenna.
    user_agent = f"search_closed_vulns/{VERSION} (Kenna Security)"
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8',
               'X-Risk-Token': api_key,
               'User-Agent': user_agent}

    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com"
    
    closed_vulns_resp = search_closed_vulns(base_url, headers)

    meta = closed_vulns_resp['meta']
    total_count = meta['total_count']
    print_info(f"Closed vulnerabilities for the last seven days: {total_count}")
