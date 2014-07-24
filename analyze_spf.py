import spf
import DNS
import sys
import socket
import string
import re

domain_list = []
spf_list = []
results = {'no_record': 0, 'hardfail': 0, 'softfail': 0,
           'neutral': 0, 'pass_all': 0, 'num_records': 0,
           'errors': 0}


def get_data(file):
    try:
        with open(file) as f:
            data = f.readlines()
            for each_line in data:
                email = each_line.strip().strip('"')
                lc_email = str(email.lower())
                #print("email: " + str(email))
                (user, domain) = lc_email.split("@")
                #print("domain: " + str(domain))
                domain_list.append(domain.strip())
        return(domain_list)
    except IOError as ioerr:
        print('IO Error: ' + str(err))
        return(none)

def lookup_spf(list_of_domains):

    for each_domain in list_of_domains:
        if domain_exist(each_domain):
            q = spf.query(i='127.0.0.1', s='localhost', h='unknown',
                receiver=socket.gethostname())
            try:
                spf_record = str(q.dns_spf(each_domain))
                print(str(each_domain) + ": " + str(spf_record))

                if 'redirect' in spf_record:
                    redir_address = re.search('redirect=(.+)', spf_record).group(1)
                    redirect_record = str(q.dns_spf(redir_address))
                    print(each_domain + " redirects to " + redirect_record)
                    classify_spf(redirect_record)
                else:
                    classify_spf(spf_record)

            except spf.PermError,x:
                print("Permanent error with " + str(each_domain))
                results['errors'] += 1
            except spf.TempError,x:
                print("Temporary error with " + str(each_domain))
                results['errors'] += 1
            except spf.AmbiguityWarning,x:
                print("Ambiguity:" + str(x))
                results['errors'] += 1

def domain_exist(domain):
    try:
        result = socket.getaddrinfo(domain, None)
        return(True)
    except:
        return(False)

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

list = get_data('query_result.csv')
#print(list)

spf_result = lookup_spf(list)

#print(spf_result)
print("Results:")
print("Total records analyzed: " + str(results['num_records']))
print("Hard Fail: " + str(results['hardfail']) + " " + str(round((100*results['hardfail']/results['num_records']), 2)) + "%")
print("Soft Fail: " + str(results['softfail']) + " " + str(round((100*results['softfail']/results['num_records']), 2)) + "%")
print("Pass All: " + str(results['pass_all']) + " " + str(round((100*results['pass_all']/results['num_records']), 2)) + "%")
print("Neutral: " + str(results['neutral']) + " " + str(round((100*results['neutral']/results['num_records']), 2)) + "%")
print("No SPF record: " + str(results['no_record']) + " " + str(round((100*results['no_record']/results['num_records']), 2)) + "%")
print("Errors: " + str(results['errors']) + " " + str(round((100*results['errors']/results['num_records']), 2)) + "%")


