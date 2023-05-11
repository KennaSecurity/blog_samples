# Vulnerabilities per Asset

Code examples for multple to ways to list assets.

This directory contains 5 files:

* loop_assets.py - Simple program that counts assets with pagenation.
* page_assets.py - Counts assets with pagenation different from `loop_assets.py`.
* page_asset_vulns.py - Collects vulnerability information per asset.
* export_assets.py - Demostrates how to export assets.
* export_asset_vulns.py - Collects vulneratibility information per asset from an asset export.
* asset_group_vulns.py - Collects vulnerability information per asset group.  See below for more details.

## asset_group_vulns.py

Obtains vulnerability information via assets in an asset group.  From that asset search, asset IDs are collected and a vulnerability search is performed using the collected asset IDs.  Output is to a configurable JSON file.  Please read the configuration file named below for details.

The asset search can be filtered by a risk meter ID.  The result of the asset search cannot have over 100,000 assets.  Remember that a risk meter ID identifies an asset group.

Installation: `pip -r requirements.txt`

Configuration file is `asset_group_vuln.yml`.

Log file is `asset_group_vuln.log`.  All runs are appended; therefore, you will need to remove periodically.

Execution:  `python asset_group_vuln.py [-r <risk_meter_id>]`

Help: `python asset_group_vuln.py --help`

## More Information
* [Acquiring Vulnerabilities per Asset](https://www.kennasecurity.com/blog/acquiring-vulnerabilities-per-asset-api/) blog
* [8 Types of High-Risk Cybersecurity Vulnerabilities](https://www.kennasecurity.com/blog/8-types-of-high-risk-cybersecurity-vulnerabilities/) blog
