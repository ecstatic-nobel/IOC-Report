#!/usr/bin/python
"""
IOC Report Configuration File
"""

# VirusTotal configurations
vt_api_key = ''

# Hybrid-Analysis configurations
ha_api_key    = ''
ha_secret_key = ''

# These settings are used to create the reports. File paths should be entered 
# as the absolute path.
input_file       = 'sample_resources.txt'
csv_output_file  = 'sample_osint_report.csv'
txt_output_file  = 'sample_osint_report.txt'
feed_output_file = 'sample_feed_report.csv'

# Web server configurations
host = '127.0.0.1'
port = 8080
