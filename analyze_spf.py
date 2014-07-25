# SPF analyzer
# Author: Demian Ginther (demian@atpay.com)

import spf
import DNS
import sys
import socket
import string
import re

# Initialize some lists and our dictionary to store our results
domain_list = []
spf_list = []
results = {'no_record': 0, 'hardfail': 0, 'softfail': 0,
           'neutral': 0, 'pass_all': 0, 'num_records': 0,
           'errors': 0}

# Read the file and strip out whitespace, quotation marks,
# and split the email addresses at the @ signs. Make sure we are
# lower case as well. Append each domain to the list and return.
# TODO: handle comma separated lists on one line (CC,BCC)
def get_data(file):
    try:
        with open(file) as f:
            data = f.readlines()
            for each_line in data:
                email = each_line.strip().strip('"')
                lc_email = str(email.lower())
                (user, domain) = lc_email.split("@")
                domain_list.append(domain.strip())
        return(domain_list)
    except IOError as ioerr:
        print('IO Error: ' + str(err))
        return(none)

# Take a list of domains and look up each one's SPF record, if
# the domain is valid. Handles redirects. DNS server can be
# changed in q, if needed
def lookup_spf(list_of_domains):
    for each_domain in list_of_domains:
        if domain_exist(each_domain):
            q = spf.query(i='127.0.0.1', s='localhost', h='unknown',
                receiver=socket.gethostname())
            try:
                spf_record = str(q.dns_spf(each_domain))
                print(str(each_domain) + ": " + str(spf_record))
                # Check for a redirect
                if 'redirect' in spf_record:
                    redir_address = re.search('redirect=(.+)', spf_record).group(1)
                    redirect_record = str(q.dns_spf(redir_address))
                    print(each_domain + " redirects to " + redirect_record)
                    classify_spf(redirect_record)
                else:
                    classify_spf(spf_record)
            # Handle spf exceptions and print to screen, increment error counter
            except spf.PermError,x:
                print("Permanent error with " + str(each_domain))
                results['errors'] += 1
            except spf.TempError,x:
                print("Temporary error with " + str(each_domain))
                results['errors'] += 1
            except spf.AmbiguityWarning,x:
                print("Ambiguity:" + str(x))
                results['errors'] += 1



# Check to see if a given domain exists in DNS, before trying to find an SPF
# record
def domain_exist(domain):
    try:
        result = socket.getaddrinfo(domain, None)
        return(True)
    except:
        return(False)

# Check the SPF record to see how it's configured and increment
# the proper counter
def classify_spf(spf_record):
    if spf_record.endswith('-all'):
        results['hardfail'] += 1
    elif spf_record.endswith('~all'):
        results['softfail'] += 1
    elif spf_record.endswith('+all'):
        results['pass_all'] += 1
    elif spf_record.endswith('?all'):
        results['neutral'] += 1
    else:
        results['no_record'] += 1
    results['num_records'] += 1

# Program that runs
list = get_data('query_result.csv')
spf_result = lookup_spf(list)

# Print out the results
# TODO: Output a nice graph?
print("Results:")
print("Total records analyzed: " + str(results['num_records']))
print("Hard Fail: " + str(results['hardfail']) + " " + str(round((100*results['hardfail']/results['num_records']), 2)) + "%")
print("Soft Fail: " + str(results['softfail']) + " " + str(round((100*results['softfail']/results['num_records']), 2)) + "%")
print("Pass All: " + str(results['pass_all']) + " " + str(round((100*results['pass_all']/results['num_records']), 2)) + "%")
print("Neutral: " + str(results['neutral']) + " " + str(round((100*results['neutral']/results['num_records']), 2)) + "%")
print("No SPF record: " + str(results['no_record']) + " " + str(round((100*results['no_record']/results['num_records']), 2)) + "%")
print("Errors: " + str(results['errors']) + " " + str(round((100*results['errors']/results['num_records']), 2)) + "%")


