#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

This script removes vulnerabilities from Couch depending on their name.
'''

import argparse
import json
import requests
import os

def main():
    #arguments parser
    parser = argparse.ArgumentParser(prog='removeByName', epilog="Example: ./%(prog)s.py")
    parser.add_argument('-d', '--db', action='store', type=str, required=True,
                        dest='db', help='DB to process')
    parser.add_argument('-n', '--name', action='store', type=str, required=True,
                        dest='name', help='Vulnerability name')
    parser.add_argument('-t', '--test', action='store_true',
                        dest='test', help='Dry run, does everything except updating the DB')
    parser.add_argument('-v', '--verbose', action='store_true',
                        dest='verbose', help='Extended output')
    parser.add_argument('--server', action='store', type=str,
                        dest='server', default="http://127.0.0.1:5985",
                        help='Server URL as http://user:password@server_ip:server_port (defaults to http://127.0.0.1:5985)')

    #arguments put in variables
    args = parser.parse_args()
    db = args.db
    name = args.name
    test = args.test
    verbose = args.verbose
    server = args.server

    fixDb(server, db, name, test, verbose)

def fixDb(server, db, name, test, verbose):
    server = str(server)
    db = str(db)

    #get all broken elements from CouchDB
    headers = {'Content-Type': 'application/json'}
    payload = { "map" : """function(doc) { if((doc.type == \"Vulnerability\" && doc.name == \""""+name+"""\") ||
                                            (doc.type == \"VulnerabilityWeb\" && doc.name == \""""+name+"""\")){ emit(doc._id, doc._rev); }}""" }

    r = requests.post(server + '/' + db + '/_temp_view', headers=headers, data=json.dumps(payload))
    response_code = r.status_code

    if response_code == 200:
        response = r.json()
        rows = response['rows']
        # ID is ID, value is REV

        if len(rows) > 0:
            print " [*[ Processing " + str(len(rows)) + " documents for " + db + " with name " + name + " ]*]"

            for row in rows:
                id = str(row['id'])
                rev = str(row['value'])

                # delete vuln
                if verbose:
                    print " - Deleting vulnerability with ID " + id
                if not test:
                    delete = requests.delete(server + '/_api/ws/' + db + '/doc/' + id + '?rev=' + rev)
                    if verbose:
                        print " -- " + delete.reason + " (" + str(delete.status_code) + ")"
            print " Done"
        else:
            print "No vulns were found in DB " + db + " with name " + name + "!"
    elif response_code == 401:
        print "Autorization required to access " + db + ", make sure to add user:pwd to server URI using --server"
    else:
        print "Error connecting to server, please verify the service is up"

if __name__ == "__main__":
    main()
