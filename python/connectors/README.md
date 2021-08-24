# Launching Connectors

This directory contains 2 files:

* connectors_auto_start.py - Starts non-file based connectors after 24 hours since the last one completed.
* show_connector_status.py - Displays connector status.  Contains helpful debug functions.  This is where the code started, but was refined into `connectors_auto_start.py`.

## Installation
To run these code examples, do:
`pip install -r requirements.txt`

The code examples use the following libraries:

* requests - handles HTTPS requests
* prettyTable - creates tables for terminals

## Run
To run the code:
* `python connectors_suto_start.py`
* `python show_connector_status.py`
