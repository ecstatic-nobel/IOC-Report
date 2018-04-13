#!/usr/bin/python

from collections import OrderedDict
from re import findall

from flask import Flask, abort, redirect, render_template, request
from werkzeug.urls import iri_to_uri

import config
from iocr_osint import Store, Report


app  = Flask(__name__)

store  = Store()
report = Report()
host   = config.host
port   = config.port
csvf   = config.csv_output_file
txtf   = config.txt_output_file

@app.route('/')
def index():
    """ """
    line = return_lines('/', 'application/')
    fity = line[1].split(',')[2]
    chsu = line[1].split(',')[3]
    if chsu == '' or not fity.startswith('application/'):
        chsu = line[1].split(',')[6]
        if chsu == '':
            return render_template('index.html', sena='%s:%s' % (host, port), chsu='{MD5}')
        else:
            return render_template('index.html', sena='%s:%s' % (host, port), chsu=chsu)
@app.route('/<file_type>')
def return_all(file_type):
    """ """
    if file_type == 'csv':    oufi = csvf
    elif file_type == 'text': oufi = txtf
    else:                     return abort(404)

    rein = store.read_input(oufi)
    foco = '\n'.join(rein)

    return render_template('response.html', text=foco)

@app.route('/<file_type>/<md5>')
def return_hash(file_type, md5):
    """ """
    if file_type != 'csv' and file_type != 'text': return abort(404)

    chsu = validate_checksum(md5)
    if chsu == None: abort(404)
    rout = '/%s/%s' % (file_type, md5)
    iobh = return_lines(rout, chsu)
    if len(iobh) < 2: abort(400)
    requ = '\n'.join(iobh)

    if file_type == 'text':
        unfd = report.flat_data(iobh, None)
        requ = '\n'.join(unfd)

    return render_template('response.html', text=requ)

@app.errorhandler(404)
def error_client(error):
    """ """
    return render_template('error_client.html'), 404

@app.errorhandler(500)
def error_server(error):
    """ """
    return render_template('error_server.html'), 500

@app.errorhandler(400)
def error_request(error):
    """ """
    return render_template('error_request.html'), 400

def return_lines(route, resource):
    """ """
    rein  = store.read_input(csvf)
    lines = []
    lines.append(rein[0])

    for line in rein: 
        print line
        if resource in line: 
            lines.append(line)
            if route == '/': break

    return lines

def validate_checksum(checksum):
    """ """
    iscu = findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', checksum)
    if len(iscu) == 1: return checksum
    else:              return None

app.run(host=host, port=port, threaded=True)
