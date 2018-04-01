# [ioc_report]  
##### Download files from URLs provided and return a CSV report containing IOCs gathered from VirusTotal and Hybrid-Analysis.  

#### Description  
This project is used as a tool to automate the process of using OSINT to find indicators of compromise (IOC) to sweep you environment for. Since this project was built around the public APIs, there is a rate limit. I used the VirusTotal rate limit (4 requests per minute at the time of writing this) as the baseline. Since the Hybrid-Analysis function of this script checks two environments (Win 7 32-bit and Win 7 64-bit), it takes approximately 45 seconds to pull the information for each URL provided. If you have access to the private API, just remove the 15 second waits and everything "should" be fine. Is 45 seconds a long time? Sure it is but this gives you more time to go do something else like flirt with your crush at work or twidle your thumbs.  

The `OUTPUTFILE` was meant to be used as a lookup in Splunk in order to do more correlation with other log sources but as with any other open-source project, use it as you best see fit. If you are a Splunk master, manipulating the lookup table should be a piece of cake.  


#### Prerequisites  
- Python 2.7.14  
- Python Requests module  
- VirusTotal API key  
- Hybrid-Analysis API key and secret  

#### Setup  
Open a terminal and run the following commands:  
```bash
mkdir ~/leunammejii
cd ~/leunammejii
git clone https://github.com/leunammejii/ioc_report.git
cd ioc_report
```

#### Basic Report  
The basic report, `basic_report.sh`, is used to pull down files and get the MIME-type, MD5, SHA256 hashes, and write the comma-separated data to a file.  

To run the script, run the following command from the project directory:  
```bash
bash basic_report.sh INPUTFILE OUTPUTFILE
```

#### Full Report  
The full report, `full_report.sh`, is used to pull down files and get the MIME-type, MD5, SHA256 hashes, requests the hashes from VirusTotal for the ones that were no longer available on the site but previously submitted by another user, request more information (extracted files, hashes, filetypes, hosts, and IP addresses) from Hybrid-Analysis, and write the comma-separated data to a file.  

To run the script, add the full path of the input and output file, the API keys for both VirusTotal and Hybrid-Analysis to config.py, and run the following command from the project directory:  
```python
python full_report.py
```

#### Read the Results  
Either one of these scripts will read a list of URLs from the `INPUTFILE` and write the data to the `OUTPUTFILE`. If you want to read the results, run the following command:  
```bash
column -t -s , OUTPUTFILE
```

Or, you can just open the `OUTPUTFILE` in Excel (LibreOffice Calc). Sample outputs can be found [here](https://github.com/leunammejii/ioc_report/blob/master/sample_basic_results.csv) (basic report) and [here](https://github.com/leunammejii/ioc_report/blob/master/sample_full_results.csv) (full report).  

#### Destroy
To remove the project completely,  run the following commands:  
```bash
rm -rf ~/leunammejii/ioc_report
```  

#### To-Do  
- [ ] Remove duplicate lines in report  
