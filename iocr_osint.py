#!/usr/bin/python
"""
Description: Creates a CSV containing information about online files using 
             VirusTotal and Hybrid-Analysis (Win 7 32-bit and 64-bit 
             environments). The intent was to append this as a lookup table in 
             Splunk. Since the was built around public API access, the script 
             should run in the background and not as an custom command.
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


global headers
headers = ','.join([
    'initial:url',       
    'initial:path',
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

class Store:
    """ """
    def __init__(self):
        """ """

    def read_input(self, infi):
        """Return contents from file as a list"""
        opfi = open(infi, 'r')
        fico = opfi.read().splitlines()
        opfi.close()

        return fico

    def norm_data(self, file_contents):
        """Return normalized data"""
        deli = []
        for line in file_contents:
            line = line.replace('hxxp', 'http')
            line = line.split(' ')[0]
            line = line.strip()
            line = line.replace('[.]', '.')
            line = line.replace('[d]', '.')
            line = line.replace('[D]', '.')
            line = line.replace('\.', '.')
            deli.append(line)
        if '/' in ''.join(deli):
            urls = [x for x in deli if x.startswith('http')]
            noda = sorted(set(urls))
        else:
            noda = sorted(set(deli))

        return noda

    def write_output(self, output_data, fileType):
        """Write contents to a file"""
        if fileType == 'c': oufi = config.csv_output_file
        if fileType == 't': oufi = config.txt_output_file

        with open(oufi, 'w') as of:
            for line in output_data: of.write('%s\n' % line)

        return

class Ioc:
    """ """
    def __init__(self):
        """ """

    def download_file(self, urls):
        """Return comma separated Iocs"""
        dofi = []
        
        for url in urls:
            path = '/'+'/'.join(url.split('/')[3:])

            try:
                resp = requests.get(url, allow_redirects=False)
                open('downloadedFile', 'wb').write(resp.content)
                fity = resp.headers.get('content-type').split(';')[0]
                md5, sha256 = self.hash_file()
                dofi.append('%s,%s,%s,%s,%s,downloaded from site' % (url,
                                                                     path,
                                                                     fity,
                                                                     md5,
                                                                     sha256))
            except:
                dofi.append('%s,%s,,,,file not found' % (url, path))

        return dofi

    def hash_file(self):
        """Return file checksums"""
        md5    = hashlib.md5()
        sha256 = hashlib.sha256()
        
        with open('downloadedFile', 'rb') as dofi:
            for chunk in iter(lambda: dofi.read(4096), b""):
                md5.update(chunk)
                sha256.update(chunk)

        os.remove('downloadedFile')

        return md5.hexdigest(), sha256.hexdigest()

    def vt_iocs(self, api_key, resource_data, resource_type, checksum):
        """Return Iocs from Virus Total."""
        if resource_type == 'u':
            api  = 'https://www.virustotal.com/vtapi/v2/url/report'
            spre = resource_data.split(',')               
            url  = spre[0]
            path = '/'+'/'.join(url.split('/')[3:])
            padi = {'apikey': api_key, 'resource': url}

            try:
                resp = requests.get(api, params=padi).json()
                time.sleep(15)

                fsid = resp['filescan_id']
                fich = fsid.split('-')[0]
                md5, sha256 = self.vt_iocs(api_key, None, 'f', fich)
                ref  = 'https://www.virustotal.com/#/file/%s/detection' % sha256
                time.sleep(15)

                if len(spre) == 1:
                    resource_data = '%s,%s,,,,download skipped,%s,%s,%s' % (resource_data,
                                                                            path,
                                                                            md5,
                                                                            sha256,
                                                                            ref)
                else:
                    resource_data = '%s,%s,%s,%s' % (resource_data, md5, sha256, ref)
            except:
                if len(spre) == 6:
                    spre = spre + ['', '', 'file never seen']
                else:
                    spre = spre + [path, '', '', '', '', '', '', 'file never seen']
                resource_data = ','.join(spre)
                time.sleep(15)
        elif resource_type == 'f':
            api  = 'https://www.virustotal.com/vtapi/v2/file/report'
            padi = {'apikey': api_key, 'resource': checksum}

            try:
                resp   = requests.get(api, params=padi).json()
                md5    = resp['md5']
                sha256 = resp['sha256']

                return md5, sha256
            except:
                return None

        return resource_data

    def ha_iocs(self, api_key, api_secret, vt_data, resource_type):
        """Return Iocs from Hybrid Analysis."""
        api  = 'https://www.hybrid-analysis.com'
        usag = {'User-agent': 'VxStream Sandbox'}
        eIDs = [100, 120]
        spvd = vt_data.split(',')
        chsu = str(spvd[0])

        if resource_type == 'u':
            chsu = str(spvd)
            inft = spvd[2]
            inre = spvd[5]
            chsu = str(spvd[4])

            if not inft.startswith('application/') or \
                inre == 'download skipped' or \
                inre == 'file not found':
                chsu = str(spvd[7])

        api  = api + "/api/summary/" + chsu
        haio = []

        for eID in eIDs:
            padi = {
                'apikey': api_key,
                'secret': api_secret,
                'environmentId': eID
            }
            
            try:
                hare = requests.get(api, headers=usag, params=padi).json()
                resp = hare['response']
                hata = ' | '.join(resp['classification_tags'])
                hamt = []
                for tysh in resp['type_short']: 
                    hamt.append(self.get_mimetype(tysh))
                haft = ' | '.join(hamt)
                haip = ' | '.join(resp['hosts'])
                hado = ' | '.join(resp['domains'])
                hacs = ' | '.join(['%s (%s)' % (x['sha256'], x['name']) for x in resp['extracted_files']])
                haih = resp['imphash']
                ref  = 'https://www.hybrid-analysis.com/sample/%s?environmentId=%s' % (chsu, str(eID))
                neli = ',,,,%s,file not submitted,,,file not submitted,%s,%s,%s,%s,%s,%s,%s' % (chsu,
                                                                                                hata,
                                                                                                haft,
                                                                                                haip,
                                                                                                hado,
                                                                                                hacs,
                                                                                                haih,
                                                                                                ref)

                if resource_type == 'u':
                    obli = vt_data.replace('http', 'hxxp').replace('.', '[.]')
                    neli = '%s,%s,%s,%s,%s,%s,%s,%s' % (obli,
                                                        hata,
                                                        haft,
                                                        haip,
                                                        hado,
                                                        hacs,
                                                        haih,
                                                        ref)

                haio.append(neli)
            except:
                neli  = ',,,,%s,file not submitted,,,file not submitted,,,,,,,file never seen' % chsu
                if resource_type == 'u':
                    obli = vt_data.replace('http', 'hxxp').replace('.', '[.]')
                    neli = '%s,,,,,,,file never seen' % obli
                haio.append(neli)
            
            time.sleep(15)

        return haio

    def get_mimetype(self, file_type):
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

        return mimetype.get(file_type, file_type)

class Report:
    """ """
    def __init__(self):
        """ """

    def full_report(self, resource_data, resource_type):
        """Generate report formatted as a CSV file"""
        csvf = config.csv_output_file
        vtak = config.vt_api_key
        haak = config.ha_api_key
        hask = config.ha_secret_key
        csex = os.path.exists(csvf)

        if csex: csco = Store().read_input(csvf)

        with open(csvf, 'a') as csof:
            if not csex:
                csco = [headers]
                csof.write('%s\n' % headers)

            for reda in resource_data:
                vtio = reda

                if resource_type == 'u':
                    vtio = Ioc().vt_iocs(vtak, reda, 'u', None)

                haio = Ioc().ha_iocs(haak, hask, vtio, resource_type)

                for line in haio:
                    if line not in csco:
                        csco.append(line)
                        csof.write('%s\n' % line)
                        csof.flush()
                        os.fsync(csof.fileno())

        return

    def flat_data(self, csv_data, resource_type):
        """Generate report formatted as a flat text file"""
        ordi = collections.OrderedDict()

        for row in csv_data[1:]:
            key = row.split(',')[0]
            if resource_type == 'c':
                key = row.split(',')[4]

            if key in ordi:
                ordi[key] = ordi[key] + [row.split(',')]
            else:
                ordi[key] = [row.split(',')]

        fida = []
        for _, vs in ordi.items():
            for index in range(len(vs[0])):
                spio = []
                for v in vs:
                    if v[index] != 'download skipped' and \
                        v[index] != 'file never seen' and \
                        v[index] != 'file not submitted' and \
                        v[index] != 'Unknown':
                        spio.append(v[index].split(' | '))
                fiio = filter(None, sum(spio, []))
                if len(fiio) == 0: continue
                unio = sorted(set(fiio))
                liio = '\n\t'.join(unio)

                fida.append('%s' % headers.split(',')[index])
                fida.append('\t%s' % liio)
            fida.append('\n-----------------------------\n')

        return fida

def main():
    """ """
    # Parse Arguments
    parser = argparse.ArgumentParser(description='Generate Ioc report.')
    parser.add_argument('-d', '--download',
                        action='store_true',
                        dest='download',
                        default=False,
                        required=False,
                        help="attempt to download files first")
    parser.add_argument('-c', '--checksum',
                        action='store_true',
                        dest='checksum',
                        default=False,
                        required=False,
                        help="skip VirustTotal and submit MD5s to Hybrid-Analysis")
    parser.add_argument('-f', '--flat',
                        action='store_true',
                        dest='flat',
                        default=False,
                        required=False,
                        help="generate report as a flat text file")
    args = parser.parse_args()

    # Initialize
    store  = Store()
    ioc    = Ioc()
    report = Report()

    csvf = config.csv_output_file

    # Normalize Input Data
    rein = store.read_input(config.input_file)
    noda = store.norm_data(rein)
    reda = noda

    # Get the Analysis Time
    urco = len(noda)
    anti = urco*.75
    if args.checksum:
        anti = urco*.5
    print 'Analysis of '\
          +str(urco)\
          +' resources will take approximately '\
          +str(anti)\
          +' minutes. Check the file periodically for updates...'

    # Attempt to Download Files
    if args.download:
        reda = ioc.download_file(noda)

    # Generate Report Formatted as a CSV File
    if args.checksum:
        report.full_report(reda, None)
    else:
        report.full_report(reda, 'u')

    # Generate Report Formatted as a Flat TXT File
    if args.flat:
        rein = store.read_input(csvf)
        if args.checksum:
            flda = report.flat_data(rein, 'c')
        else:
            flda = report.flat_data(rein, 'u')
        store.write_output(flda, 't')

if __name__ == '__main__':
    main()
