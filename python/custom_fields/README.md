# Custom Fields

This directory contains code samples that:

* list unique custom fields with values
* searches for a custom field with a value
* updates a vulnerability custom field with a new value

There are four files:

* blog_list_custom_fields.py - Code that is used in the [Custom Field blog](https://www.kennasecurity.com/blog/custom-fields/).
* list_custom_fields.py - Latest version that lists unique custom fields and their values.
* search_custom_field.py - Searchs vulnerabilities for a custom field and value.
* update_custom_field.py - Updates a custom field for one vulnerability.

Bulk update vulnerabilities is covered in `cisa_risk_meter/build_cisa_risk_meter.py`.

## Directions

1. Install the progrm the program by doing: `pip -r requirements.txt`.
1. Set the environent variable $KENNA_API_KEY
   * In Windows: https://docs.oracle.com/en/database/oracle/machine-learning/oml4r/1.5.1/oread/creating-and-modifying-environment-variables-on-windows.html
   * In DOS: `set KENNA_API_KEY=<your API key>`
   * In Linux: `export KENNA_API_KEY='<your API key>'`
1. Run the program: `python list_custom_field.py`

### Options
You can also run the script with a previous search ID. This will first look for `vulns_<search ID>.jsonl` and then `vulns_<search ID>.gz`. If neither is found, the script will check the export status.

`python list_custom_fields.py -h` prints help.

## Sample Output

```
> custom_fields % python list_custom_fields.py 
List Unique Custom Fields
New search ID: 1599415 with 400443 vulnerabilities.
Sleeping for 5 seconds.  (91 out of 240.0)
Gunzipping file vulns_1599415.gz to vulns_1599415.jsonl
File vulns_1599415.gz gunzipped to vulns_1599415.jsonl
Counting lines in vulns_1599415.jsonl
File: vulns_1599415.jsonl with 400443 vulns.
Opening vulns_1599415.jsonl for processing.
................................................................................................................................................................................................................................................................................................................................................................................................................
Total 400443 vulns processed.
21 unique custom fields discovered.
uniq_custom_fields.csv is now available.
> custom_fields %
```

