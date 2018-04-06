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
import collections
import csv
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
        self.headers = ','.join([
            'initial:url',       
            'initial:resource',
            'initial:filetype',
            'initial:md5',
            'initial:sha256',
            'initial:reference',
            'vt:md5',
            'vt:sha256',
            'vt:reference',
            'ha:tags',
            'ha:filetype',
            'ha:hosts',
            'ha:domains',
            'ha:hashes',
            'ha:imphash',
            'ha:reference'
        ])
        self.tmp_output_file = '/tmp/%s.tmp' % config.csv_output_file.rsplit('/', 1)[1]

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
                data.append('%s,%s,%s,%s,%s,downloaded from site' % (url, resource, filetype, md5, sha256))
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

    def full_report(self, file_data):
        """Generate report formatted as a CSV file"""
        csvExists = os.path.exists(config.csv_output_file)
        if csvExists:
            csv_contents = self.read_input(config.csv_output_file)

        with open(config.csv_output_file, 'a') as csvOutputFile:
            if not csvExists:
                csvOutputFile.write('%s\n' % self.headers)
                csv_contents = [self.headers]

            for fd in file_data:
                vtd = self.vt_report(fd, config.vt_api_key, 'url', None)
                had = self.ha_report(config.ha_api_key, config.ha_secret_key, vtd)

                for line in had:
                    if line not in csv_contents:
                        csvOutputFile.write('%s\n' % line)
                        csvOutputFile.flush()
                        os.fsync(csvOutputFile.fileno())

        return

    def vt_report(self, file_data, api_key, resource_type, hash):
        """Return IOCs from Virus Total."""
        if resource_type == 'url':
            vt       = 'https://www.virustotal.com/vtapi/v2/url/report'
            split    = file_data.split(',')               
            url      = split[0]
            resource = '/'+'/'.join(url.split('/')[3:])
            uparams  = {'apikey': api_key, 'resource': url}

            try:
                raw_response = requests.get(vt, params=uparams).json()
                time.sleep(15)

                filescan_id = raw_response['filescan_id']
                file_hash   = filescan_id.split('-')[0]
                md5, sha256 = self.vt_report(None, api_key, 'file', file_hash)
                reference   = 'https://www.virustotal.com/#/file/%s/detection' % sha256
                time.sleep(15)

                if len(split) == 1:
                    file_data = '%s,%s,,,,download skipped,%s,%s,%s' % (file_data, resource, md5, sha256, reference)
                else:
                    file_data = '%s,%s,%s,%s' % (file_data, md5, sha256, reference)
            except:
                if len(split) == 6:
                    split = split + ['', '', 'file never seen']
                else:
                    split = split + [resource, '', '', '', '', '', '', 'file never seen']
                file_data = ','.join(split)
                time.sleep(15)
        elif resource_type == 'file':
            vt      = 'https://www.virustotal.com/vtapi/v2/file/report'
            fparams = {'apikey': api_key, 'resource': hash}

            try:
                raw_response = requests.get(vt, params=fparams).json()
                md5          = raw_response['md5']
                sha256       = raw_response['sha256']

                return md5, sha256
            except:
                return None

        return file_data

    def ha_report(self, api_key, api_secret, vtd):
        """Return IOCs from Hybrid Analysis."""
        ha      = 'https://www.hybrid-analysis.com'
        ua      = {'User-agent': 'VxStream Sandbox'}
        eIDs    = [100, 120]
        split   = vtd.split(',')
        dlft    = split[2]
        dlref   = split[5]
        if not dlft.startswith('application/') or dlref == 'download skipped' or dlref == 'file not found':
            sha256 = split[7]
        else:
            sha256 = split[4]
        request = ha + "/api/summary/" + sha256
        had     = []

        for eID in eIDs:
            params = {'apikey': api_key, 'secret': api_secret, 'environmentId': eID}
            
            try:
                raw_resp = requests.get(request, headers=ua, params=params).json()
                response = raw_resp['response']
                tags     = ' | '.join(response['classification_tags'])
                mimetype = []
                for ts in response['type_short']: 
                    mimetype.append(self.get_mimetype(ts))
                filetype = ' | '.join(mimetype)
                hosts    = ' | '.join(response['hosts'])
                domains  = ' | '.join(response['domains'])
                hashes   = ' | '.join(['%s (%s)' % (x['sha256'], x['name']) for x in response['extracted_files']])
                imphash  = response['imphash']
                ref      = 'https://www.hybrid-analysis.com/sample/%s?environmentId=%s' % (sha256, str(eID))
                obfline  = vtd.replace('http', 'hxxp').replace('.', '[.]')
                newline  = '%s,%s,%s,%s,%s,%s,%s,%s' % (obfline, tags, filetype, hosts, domains, hashes, imphash, ref)
                had.append(newline)
            except:
                obfline  = vtd.replace('http', 'hxxp').replace('.', '[.]')
                newline  = '%s,,,,,,,file never seen' % obfline
                had.append(newline)
            
            time.sleep(15)

        return had

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

    def flat_report(self):
        """Generate report formatted as a flat text file"""
        csv_data = self.read_input(config.csv_output_file)
        grouped  = collections.OrderedDict()

        for row in csv_data[1:]:
            key = row.split(',')[0]
            if key in grouped:
                grouped[key] = grouped[key] + [row.split(',')]
            else:
                grouped[key] = [row.split(',')]

        with open(config.txt_output_file, 'w') as txtOutputFile:
            for _, values in grouped.items():
                for index in range(len(values[0])):
                    split_iocs    = [x[index].split(' | ') for x in values]
                    filtered_iocs = filter(None, sum(split_iocs, []))
                    if len(filtered_iocs) == 0: continue
                    uniq_iocs = sorted(set(filtered_iocs))
                    list_iocs = '\n\t'.join(uniq_iocs)

                    txtOutputFile.write('%s\n' % self.headers.split(',')[index])
                    txtOutputFile.write('\t%s\n' % list_iocs)
                txtOutputFile.write('\n-----------------------------\n\n')
        txtOutputFile.close()

        return

def main():
    """ """
    # Parse Arguments
    parser = argparse.ArgumentParser(description='Generate IOC report.')
    parser.add_argument('-d', '--download',
                        action='store_true',
                        dest='download',
                        required=False,
                        help="attempt to download files first")
    parser.add_argument('-f', '--flat',
                        action='store_true',
                        dest='flat',
                        required=False,
                        help="generate report as a flat text file")
    parser.set_defaults(download=False)                 
    parser.set_defaults(flat=False)
    args = parser.parse_args()
    
    # Normalize Input Data
    iocr = IOCR()
    read_input = iocr.read_input(config.input_file)
    norm_data  = iocr.norm_data(read_input)
    file_data  = norm_data

    # Get the Analysis Time
    url_count     = len(norm_data)
    analysis_time = url_count*.75
    print 'Analysis of '+str(url_count)+' URLs will take approximately '+str(analysis_time)+' minutes. Check the file periodically for updates...'

    # Attempt to Download Files
    if args.download:
        file_data  = iocr.download_file(norm_data)

    # Generate Report Formatted as a CSV File
    iocr.full_report(file_data)

    # Generate Report Formatted as a Flat TXT File
    if args.flat:
        iocr.flat_report()

if __name__ == '__main__':
    main()
