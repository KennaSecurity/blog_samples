# [List Unique Asset Tags Part 1 Blog](https://www.kennasecurity.com/blog/listing-unique-asset-tags-part-1/)

Code example that builds a CSV containing unique asset tags the number of assets the tag is attached to.

This directory contains the following files:

* blog1_uniq_asset_tags.py - Code that is used for the upcoming blog that builds a CSV containing unique asset tags.
* connector_asset_tags.py - identifies scanner connector tags for assets.
* export_assets.py - stand-alone program that does an asset export.

## Directions for blog1_uniq_asset_tags.py

1. Install the progrm the program by doing: `pip -r requirements.txt`.
1. Set the environent variable $KENNA_API_KEY
   * In Windows: https://docs.oracle.com/en/database/oracle/machine-learning/oml4r/1.5.1/oread/creating-and-modifying-environment-variables-on-windows.html
   * In DOS: `set KENNA_API_KEY=<your API key>`
   * In Linux: `export KENNA_API_KEY='<your API key>'`
1. Run the program: `python blog1_uniq_asset_tags.py`

### Options
You can also run the script with a previous search ID. This will first look for `asset_<search ID>.jsonl` and then `asset_<search ID>.gz`. If neither is found, the script will check the export status.

`python blog1_uniq_asset_tags.py -h` prints help.

## Sample Output
```
Get Unique Asset Tags
New search ID: 1441359 with 40385 assets
Sleeping for 10 seconds. (60)
Unzipping file assets_1441359.gz to assets_1441359.jsonl
File assets_1441359.gz unzipped to assets_1441359.jsonl
Counting lines in assets_1441359.jsonl
File: assets_1441359.jsonl with 40385 assets.

469 unique asset tags discovered.
uniq_asset_tags.csv is now available.
```

## Directions for connector_asset_tags.py

1. Install the progrm the program by doing: `pip -r requirements.txt`.
1. Set the environent variable $KENNA_API_KEY
   * In Windows: https://docs.oracle.com/en/database/oracle/machine-learning/oml4r/1.5.1/oread/creating-and-modifying-environment-variables-on-windows.html
   * In DOS: `set KENNA_API_KEY=<your API key>`
   * In Linux: `export KENNA_API_KEY='<your API key>'`
1. Run the program: `python connector_asset_tags.py`

### Options
You can also run the script with a previous search ID. This will first look for `asset_<search ID>.jsonl` and then `asset_<search ID>.gz`. If neither is found, the script will check the export status.

`python connector_asset_tags.py -h` prints help.

The input file, `scanner_tags.txt` contains the scanner connector tags that will be used to identify assets. Each line of the file contains one scanner connector tag.

### Notes
* It takes approximately four hours 15 minutes to process 50,000 assets.
* The log file is `connector_asset_tags.log`.  The file has to be manually removed to start with a clean log.

