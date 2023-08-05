# Vulnerabilities' Details Code Examples

## Get Vulneraibilities' Details with Field Selection

* blog_get_vuln_details.py - Obtains the vulnerability details along with some other fields and creates JSONL file.

### Intallation
`pip -r requirements.txt`

### Operations
* `python blog_get_vuln_details.py -h` for help
* `python blog_get_vuln_details.py` to export and process.
* `python blog_get_vuln_details.py <export ID>` to process existing export.

As in all code in the blog_samples repo, you must set `KENNA_API_KEY` environment variable.  Also the script uses the variable `base_url` which needs to be verified that it is correct for your server.
