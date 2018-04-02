#!/usr/bin/python
"""
Description: Creates a CSV containing information about online files using VirusTotal 
             and Hybrid-Analysis (Win 7 32-bit and 64-bit environments). The intent 
             was to append this as a lookup table in Splunk. Since the was built 
             around public API access, the script should run in the background and not 
             as an custom command.
Usage: bash full_report.py
"""

import argparse
import hashlib
import os
import requests
import sys
import time
import config


class IOCR:
    """ """
    def __init__(self):
        """ """

    def read_input(self, inputFile):
        """Return contents from file"""
        open_file     = open(inputFile, 'r')
        file_contents = open_file.read().splitlines()
        open_file.close()

        return file_contents

    def norm_data(self, file_contents):
        """Return normalized data"""
        do_protocol = [x.replace('hxxp', 'http') for x in file_contents]
        no_comment  = [x.split(' ')[0] for x in do_protocol]
        no_space    = [x.strip() for x in no_comment]
        show_period = [x.replace('[.]', '.').replace('[d]', '.').replace('[D]', '.').replace('\.', '.') for x in no_space]
        url_only    = [x for x in show_period if x.startswith('http')]
        sorted_data = sorted(set(url_only))

        return sorted_data

    def download_file(self, urls):
        """Return comma separated IOCs"""
        data = []
        
        for url in urls:
            resource = '/'+'/'.join(url.split('/')[3:])
            try:
                results     = requests.get(url, allow_redirects=False)
                open('downloadedFile', 'wb').write(results.content)
                filetype    = results.headers.get('content-type').split(';')[0]
                md5, sha256 = self.hash_file()
                data.append('%s,%s,%s,%s,%s,download' % (url, resource, filetype, md5, sha256))
            except:
                data.append('%s,%s,,,,file not found' % (url, resource))

        return data

    def hash_file(self):
        """Return file checksums"""
        md5    = hashlib.md5()
        sha256 = hashlib.sha256()
        
        with open('downloadedFile', "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha256.update(chunk)

        os.remove('downloadedFile')

        return md5.hexdigest(), sha256.hexdigest()

    def vt_report(self, file_data, api_key, resource_type, hash):
        """GET results from Virus Total."""
        if resource_type == 'url':
            vt = 'http://www.virustotal.com/vtapi/v2/url/report'

            for line in file_data:
                split    = line.split(',')               
                url      = split[0]
                resource = '/'+'/'.join(url.split('/')[3:])

                if len(split) == 6:
                    filetype  = split[2]
                    if filetype.startswith('application'): continue

                uparams   = {'apikey': api_key, 'resource': url}

                try:
                    raw_response = requests.get(vt, params=uparams).json()
                    time.sleep(15)

                    filescan_id = raw_response['filescan_id']
                    file_hash   = filescan_id.split('-')[0]
                    md5, sha256 = self.vt_report(None, api_key, 'file', file_hash)
                    time.sleep(15)

                    index = file_data.index(line)
                    file_data[index] = '%s,%s,,%s,%s,osint-virustotal' % (url, resource, md5, sha256)
                except:
                    if len(split) == 6:
                        split[5] = 'file not found'
                    else:
                        split    = split + ['', '', '', '', '']
                        split[5] = 'file not found'
                    split[1]         = resource
                    index            = file_data.index(line)
                    file_data[index] = ','.join(split)
                    time.sleep(15)
        elif resource_type == 'file':
            vt      = 'http://www.virustotal.com/vtapi/v2/file/report'
            fparams = {'apikey': api_key, 'resource': hash}

            try:
                raw_response = requests.get(vt, params=fparams).json()
                md5          = raw_response['md5']
                sha256       = raw_response['sha256']

                return md5, sha256
            except:
                return None

        return file_data

    def ha_report(self, api_key, api_secret, vt_report):
        """GET results from Hybrid Analysis."""
        server     = 'https://www.hybrid-analysis.com'
        user_agent = {'User-agent': 'VxStream Sandbox'}
        eIDs       = [100, 120]
        ilist      = []

        for line in vt_report:
            split   = line.split(',')
            sha256  = split[4]
            request = server + "/api/summary/" + sha256

            for eID in eIDs:
                params = {'apikey': api_key, 'secret': api_secret, 'environmentId': eID}
                
                try:
                    raw_resp = requests.get(request, headers=user_agent, params=params).json()
                    response = raw_resp['response']
                    tags     = ' | '.join(response['classification_tags'])
                    hosts    = ' | '.join(response['hosts'])
                    hashes   = ' | '.join(['%s (%s)' % (x['sha256'], x['name']) for x in response['extracted_files']])
                    domains  = ' | '.join(response['domains'])
                    imphash  = response['imphash']
                    mimetype = []
                    for ts in response['type_short']:
                        mimetype.append(self.get_mimetype(ts))
                    filetype = ' | '.join(mimetype)
                    obfline  = line.replace('http', 'hxxp').replace('.', '[.]')
                    newline  = '%s,%s,%s,%s,%s,%s,%s,%s' % (obfline, tags, filetype, hosts, domains, hashes, imphash, str(eID))
                    ilist.append(newline)
                except:
                    obfline  = line.replace('http', 'hxxp').replace('.', '[.]')
                    newline  = '%s,,,,,,,' % obfline
                    ilist.append(newline)
                
                time.sleep(15)

        ha_report = self.dedup_report(ilist)

        return ha_report

    def get_mimetype(self, ts):
        """Return MIME type"""
        mimetype = {
            'doc'        : 'application/msword',
            'docx'       : 'application/msword',
            'empty'      : 'inode/x-empty',
            'flash'      : 'application/x-shockwave-flash',
            'java'       : 'application/java-archive',
            'javascript' : 'application/javascript',
            'msi'        : 'application/octet-stream',
            'pdf'        : 'application/pdf',
            'peexe'      : 'application/exe',
            'perl'       : 'application/x-perl',
            'ppt'        : 'application/vnd.ms-powerpoint',
            'pptx'       : 'application/vnd.ms-powerpoint',
            'ps'         : 'application/postscript',
            'python'     : 'application/python',
            'sh'         : 'application/x-sh',
            'vbs'        : 'application/x-vbs',
            'xls'        : 'application/vnd.ms-excel',
            'xlsx'       : 'application/vnd.ms-excel',
            'zip'        : 'application/zip'
        }

        return mimetype.get(ts, ts)

    def dedup_report(self, ilist):
        """Return a unique list of the report."""
        tlist = []

        for line in ilist:
            if line.endswith(',100') or line.endswith(',120'):
                split = line.split(',')
                tline = ','.join(split[:-1])
                if tline in tlist: continue
                tlist.append(tline)

                sha256      = split[4]
                eID         = split[-1]
                ref         = 'https://www.hybrid-analysis.com/sample/' + sha256 + '?environmentId=' + eID
                eIDi        = split.index(split[-1])
                split[eIDi] = ref
                vtri        = ilist.index(line)
                ilist[vtri] = ','.join(split)

        return sorted(set(ilist))

    def write_output(self, outputFile, data):
        """Write output to file"""
        of_exists = os.path.isfile(outputFile)
        header    = self.get_headers()

        with open(outputFile, 'a') as output:
            if not of_exists: output.write(header)
            for line in data:
                output.write('%s\n' % line)
        output.close()

        return

    def get_headers(self):
        """Return headers as a string."""
        headers = [
            'initial:url',
            'initial:resource',
            'initial:filetype',
            'initial:md5',
            'initial:sha256',
            'initial:reference',
            'ha:tags',
            'ha:filetype',
            'ha:hosts',
            'ha:domains',
            'ha:hashes',
            'ha:imphash',
            'ha:reference\n'
        ]

        return ','.join(headers)

def main():
    """ """
    # Parse Arguments
    parser = argparse.ArgumentParser(description='Generate IOC report.')
    parser.add_argument('-d', '--download',
                        action='store_true',
                        dest='download',
                        required=False,
                        help="attempt to download files first")
    parser.set_defaults(download=False)                    
    args = parser.parse_args()
    
    # Normalize Input Data
    iocr = IOCR()
    read_input = iocr.read_input(config.input_file)
    norm_data  = iocr.norm_data(read_input)
    file_data  = norm_data

    # Get the Analysis Time
    url_count     = len(norm_data)
    analysis_time = url_count*.75
    print 'Analysis of '+str(url_count)+' URLs will take approximately '+str(analysis_time)+' minutes. Hang tight...'

    # Attempt to Download Files
    if args.download:
        file_data  = iocr.download_file(norm_data)

    # Attempt to Get IOCs from VirusTotal
    vtr = iocr.vt_report(file_data, config.vt_api_key, 'url', None)

    # Attempt to Get IOCs from Hybrid-Analysis
    har = iocr.ha_report(config.ha_api_key, config.ha_secret_key, vtr)

    # Write Output to File
    iocr.write_output(config.output_file, har)

if __name__ == '__main__':
    main()
