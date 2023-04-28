# Create a CISA Risk Meter

Code example that builds a Kenna Security risk meter based on CISA catalog vulnerabilities.

This directory contains the following files:

* build_cisa_risk_meter.py - Latest version. Creates or updates a Kenna Security risk meter base of the CISA catalog vulnerabilities.
* blog_build_cisa_risk_meter.py - Code that is used for the [blog](https://www.kennasecurity.com/blog/create-a-cisa-risk-meter/). Creates or updates a Kenna Security risk meter base of the CISA catalog vulnerabilities.
* get_cisa_catalog.py - stand-alone program that obtains the CISA vulnerability catalog.

## Directions

1. Install the progrm the program by doing: `pip -r requirements.txt`.
1. In your Kenna Security UI, create a custom field, "CISA".  For details see: 
[Creating a Custom Field](https://help.kennasecurity.com/hc/en-us/articles/201921738-Creating-a-Custom-Field)
Note the custom field ID, you might need this.
1. Set the environent variable $KENNA_API_KEY
   * In Windows: https://docs.oracle.com/en/database/oracle/machine-learning/oml4r/1.5.1/oread/creating-and-modifying-environment-variables-on-windows.html
   * In DOS: `set KENNA_API_KEY=<your API key>`
   * In Linux: `export KENNA_API_KEY='<your API key>'`
1. If your Kenna Security API server's URL is not `api.kennasecurity.com`, then edit `KENNA_BASE_URL` in build_cisa_risk_meter.py to the correct API server URL.
1. Run the program: `python build_cisa_risk_meter.py`

## Sample Output
```
Build CISA Exploited Vulnerabilities Risk Meter

400329 vulnerabilities with CISA custom field.
Search vulnerabilities associated with CISA CVE IDs
......................................................................................
......................................................................................
......................................................................................
......................................................................................
......................................................................................
......................................................................................
.....................................................................................
.........
CISA Exploited Vulnerabilities created with 1577 vulnerabilities updated.
```

## Reference
* [How to Create a CISA Risk Meter](https://www.kennasecurity.com/blog/create-a-cisa-risk-meter/)
* [Why You Should Be Using the CISA Catalog](https://www.darkreading.com/vulnerabilities-threats/why-you-should-be-using-cisa-s-catalog-of-exploited-vulns)

