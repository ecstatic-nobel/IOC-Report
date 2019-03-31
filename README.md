# DEPRECATED: Moving to the OSweep Project (https://github.com/ecstatic-nobel/osweep)  
---

# [IOC Report]  
##### Generate a report containing IOCs gathered from VirusTotal and Hybrid-Analysis.  

#### Description  
This project is used as a tool to automate the process of gathering and sharing indicators of compromise (IOC) from VirusTotal or Hybrid-Analysis to sweep your environment. Since this project was built around public APIs, there is a rate limit. I used the VirusTotal rate limit (4 requests per minute at the time of writing this) as the baseline. Since the Hybrid-Analysis function of this script checks two environments (Win 7 32-bit and Win 7 64-bit), it takes approximately 45 seconds to pull the information for each URL provided when generating the full report. Since the `iocr_checksum.sh` script only downloads the files and provides the filetypes and checksums, this should be 10x faster (FILE DOWNLOAD TIME x NUMBER OF URLS PROVIDED). If you have access to the private API, you should be able to remove the 15 second waits and everything "should" be fine (I haven't check the rate limits for the private API because I'm broke). Is 45 seconds a long time? Sure it is but this gives you more time to go do something else like flirt with your crush at work or twidle your thumbs.  

The `OUTPUTFILE` was meant to be used as a lookup table in Splunk in order to do more correlation with other log sources but as with any other open-source project, use it as you best see fit. If you are a Splunk master, manipulating the lookup table should be a piece of cake. This file is also used to do with the provided web service in order to share and pivot off the MD5 checksums.  


#### Prerequisites  
- Python 2.7.14  
- Python Flask module  
- Python Requests module  
- VirusTotal API key  
- Hybrid-Analysis API key and secret  

#### Setup  
Open a terminal and run the following commands:  
```bash
git clone https://github.com/ecstatic-nobel/IOC-Report.git
cd IOC-Report
```

#### Latest Features  
v0.0.1 - Created project to download files from a list of URLs, get the checksums of the downloaded files, submit the URLs to VirusTotal for checksums of the last file analyzed, and finally submit the correct checksums to Hybrid-Analysis for a summary of the IOCs.  
v0.0.2 - Added the option to skip the file download.  
v0.0.3 - Added support to submit a list of hashes straight to Hybrid-Analysis.  
v0.0.4 - Added a web service to centralize IOC sharing.  
v0.0.5 - Added the option to pull the latest summaries from the Hyrid-Analysis feed. Added support to search the web service for any IOC.  

#### Download Report  
The download report, `iocr_checksum.sh`, is used to download the files, get the MIME-type, MD5, SHA256 hashes, remove the files, and write the comma-separated data to a file.  

To run the script, run the following command from the project directory:  
```bash
bash iocr_checksum.sh INPUTFILE OUTPUTFILE
```

#### OSINT Report  
The OSINT report, `iocr_osint.py`, is used to download the files, get the MIME-type, MD5, SHA256 hashes, remove the files, requests the checksums from VirusTotal for the last downloaded file it analyzed, request more information (filetypes, IP addresses, domains, and extracted file checksums) from Hybrid-Analysis, and write the data to a file. There are two report types:  
- Flat (simple text file listing the IOCs by the provided resources)  
- CSV (to be used as a lookup table in Splunk, auto-generated)  

You can request both at the same time if needed.  

To run the script, add the API keys for both VirusTotal and Hybrid-Analysis to `config.py`, add the full path of the input and output files to `config.py`, and run the following command from the project directory:  
```
python iocr_osint.py [--flat]
```

This will query VirusTotal for the hashes of the last downloaded the files from the URLs provided. If you want to download the files first to get the hashes, run the following command:  
```
python iocr_osint.py [--flat] --download
```

If you want to skip VirusTotal and submit hashes to Hybrid-Analysis, load the hashes into the `INPUTFILE` specified in the config, and run the following command:  
```
python iocr_osint.py [--flat] --checksum
```

If you want to pull the latest summaries from the feed Hybrid-Analysis (a cron job running once a day should be plenty), run the following command:  
```
python iocr_osint.py [--flat] --feed
```

#### Read the Results  
Both of these scripts will read a list of URLs or MD5 checksums from the `INPUTFILE` and write the data to the `OUTPUTFILE`. If you want to read the results of the CSV file from the commandline, run the following command:  
```bash
column -t -s , OUTPUTFILE
```

Or, you can open the `OUTPUTFILE` in Excel (LibreOffice Calc). Sample outputs can be found [here](https://github.com/ecstatic-nobel/IOC-Report/blob/master/sample_checksum_report.csv) (download report), [here](https://github.com/ecstatic-nobel/IOC-Report/blob/master/sample_osint_report.csv) (CSV report), and [here](https://github.com/ecstatic-nobel/IOC-Report/blob/master/sample_osint_report.txt) (flat text report).  

#### OSINT Web Server  
This project also comes with a simple web server used to easily share the IOCs seen in your environment. Add the IP address of the host to the `host` parameter and the port the server should listen on to the `port` parameter in the `config.py` file. Once the file is saved, run the following command:  
```bash
sudo python osint_web.py
```

Once the service has started, anyone with access to the URL, `http://HOST:PORT/` (default: http://127.0.0.1:8080), will be able to:  
- Get a list of all the IOCs as a CSV  
```bash
curl http://HOST:PORT/csv
```

- Get data from the Hybrid-Analysis feed as a CSV  
```bash
curl http://HOST:PORT/feed
```

- Get a list of all the IOCs as a flat text file  
```bash
curl http://HOST:PORT/text
```

- Pivot off an IOC and return data as a flat text (or CSV) file  
```bash
curl http://127.0.0.1:8080/csv/02244fbf2ba61afdf461f5e8cfdb19f4
```

NOTE: Pivoting off of the `/feed` will always format the ouput as a CSV.  

Now you have a way to create content based on this shared information.  

#### Destroy
To remove the project completely,  run the following commands:  
```bash
rm -rf IOC-Report
```  

#### Things to Know  
- If the MIME type of the `initial:filetype` does not start with `application/`, only use the IOCs with headers like `vt:` and `ha:` because the script submitted the SHA256 checksums from VirusTotal to Hybrid-Analysis.  
- If the MIME type of the `initial:filetype` starts with `application/` and you chose the option to download the file, know that any indicators found with VirusTotal are from the last file they downloaded from the site. Since you just downloaded the file, their indicators may be from an older file (but if the initial and vt checksums match, you're good to go). If this is the case, the script will submit the SHA256 checksums of the file you downloaded to Hybrid-Analysis.  
- If the MIME type of the `initial:filetype` starts with `text/`, you may get a different hash each time if you select the option to download it since something within the HTML may have changed since the last download.  
- The script uses two environments (Win 7 32-bit and 64-bit) in Hybrid-Analysis. There may be cases where the you get the message `file never seen` for one environment and not the other.  

#### To-Do  
- [ ] Output request to web service in Json  
- [ ] POST a list a URLs or checksums to the service to validate  

---
# DEPRECATED: Moving to the OSweep Project (https://github.com/ecstatic-nobel/osweep)  
