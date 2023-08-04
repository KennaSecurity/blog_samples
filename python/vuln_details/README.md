# Vulnerabilities' Details Code Examples

## Get Vulneraibilities' Details with Field Selection

* blog_get_vuln_details.py - Obtains the vulnerability details along with some other fields and creates three files, one in JSONL, one in formated JSON, and one in HTML.  The infomation is obtained via vulnerability exports.

### Intallation
`pip -r requirements.txt`

### Operations
* `python blog_get_vuln_details.py -h` for help
* `python blog_get_vuln_details.py` to export and process.
* `python blog_get_vuln_details.py <export ID>` to process existing export.

*Note:* "pau" means "done" in Hawaiian.
