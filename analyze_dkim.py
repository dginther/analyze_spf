# DKIM analyzer
# Author: Demian Ginther (demian@atpay.com)

import dkim
import os
import email.utils
import re
import subprocess
import json
from pylab import * 


results = {'dkim_valid_spf_pass': 0,
           'dkim_valid_spf_none': 0,
           'dkim_valid_spf_fail': 0,
           'dkim_none_spf_pass': 0,
           'dkim_none_spf_none': 0,
           'dkim_none_spf_fail': 0,
           'dkim_invalid_spf_pass': 0,
           'dkim_invalid_spf_none': 0,
           'dkim_invalid_spf_fail': 0,
           'total': 0,
          }

path = '/Users/demian/customercare_email_subset/'
spamc_executable ='/Users/demian/bin/spamc'

listing = os.listdir(path)

for infile in listing:
  try:
    with open(path + infile) as f:
      # Get spamassassin score from spamd. Obviously will fail if you are not running spamd.
      spamassassin_score = str(subprocess.check_output([spamc_executable + " -c <" + path + infile], shell=True)).strip()
      (spamassassin_score,trash) = spamassassin_score.split("/")

      msg = f.read()


      # Get email address from email
      from_address = re.search("From: (.+)", msg).group(1)
      if "<" in from_address or ">" in from_address:
        from_address = re.search("<(.+)>", from_address).group(1)

      #Get Domain from email address
      from_address = str(from_address.lower())
      (user, domain) = from_address.split("@")

      # Get spf result from email
      spf_result = re.search('spf=(\S+)', msg).group(1)

      # Get DKIM result
      dkim_present = re.search('^DKIM-Signature', msg, re.MULTILINE)

      # If we have a DKIM signature, verify it. If not, DKIM = none
      if dkim_present:
        try:
          dkim_result = dkim.verify(msg)
        except DKIMException as x:
          print('DKIM Exception: ' + str(x))
      else:
        dkim_result = 'none'

      # Evaluate results according to our rules

      # DKIM valid, SPF pass
      if dkim_result == True and spf_result == 'pass':
        results['dkim_valid_spf_pass'] += 1
      # DKIM valid, SPF none
      elif dkim_result == True and (spf_result == 'neutral' or spf_result == 'none'):
        results['dkim_valid_spf_none'] += 1
      # DKIM valid, SPF fail
      elif dkim_result == True and (spf_result == 'fail' or spf_result == 'softfail' or spf_result == 'temperror' or spf_result == 'permerror'):
        results['dkim_valid_spf_fail'] += 1
      # DKIM none, SPF pass
      elif dkim_result == 'none' and spf_result == 'pass':
        results['dkim_none_spf_pass'] += 1
      # DKIM none, SPF none
      elif dkim_result == 'none' and (spf_result == 'neutral' or spf_result == 'none'):
        results['dkim_none_spf_none'] += 1
      # DKIM none, SPF fail
      elif dkim_result == 'none' and (spf_result == 'fail' or spf_result == 'softfail' or spf_result == 'temperror' or spf_result == 'permerror'):
        results['dkim_none_spf_fail'] += 1
      # DKIM invalid, SPF pass
      elif dkim_result == False and spf_result == 'pass':
        results['dkim_invalid_spf_pass'] += 1
      # DKIM invalid, SPF none
      elif dkim_result == False and (spf_result == 'neutral' or spf_result == 'none'):
        results['dkim_invalid_spf_none'] += 1
      # DKIM invalid, SPF fail
      elif dkim_result == False and (spf_result == 'fail' or spf_result == 'softfail' or spf_result == 'temperror' or spf_result == 'permerror'):
        results['dkim_invalid_spf_fail'] += 1
      # Increment the number of records we looked at
      results['total'] += 1

      # Print results to screen
      print json.dumps([str(from_address), {'Filename': str(infile), 'DKIM': str(dkim_result), 'SPF': str(spf_result), 'Spam_Score': str(spamassassin_score)}])
      #print("{\"" + str(from_address) + "\": {" + "\"Filename\": \"" + str(infile) + "\", " + "\"DKIM\": \"" + str(dkim_result) + "\", \"SPF\": \"" + str(spf_result) + "\", \"Spam_Score\": \"" + str(spamassassin_score) +"\"}}")
  except IOError as ioerr:
    print('IO Error: ' + str(ioerr))

print("Results: ")
#print("Total records: " + str(results['total']))
#print("Valid DKIM: " + str(results['valid']))
#print("Invalid or no DKIM: " + str(results['invalid']))
print(results)

figure(1, figsize=(6,6))
ax = axes([0.1, 0.1, 0.8, 0.8])

labels = 'DKIM Valid, SPF Pass', 'DKIM Valid, SPF None', 'DKIM Valid, SPF Fail', 'DKIM None, SPF Pass', 'DKIM None, SPF None', 'DKIM None, SPF Fail', 'DKIM Invalid, SPF Pass', 'DKIM Invalid, SPF None', 'DKIM Invalid, SPF Fail'

fracs = [(results['total']/results['dkim_valid_spf_pass']),(results['total']/results['dkim_valid_spf_none']),(results['total']/results['dkim_valid_spf_fail']),
	(results['total']/results['dkim_none_spf_pass']),(results['total']/results['dkim_none_spf_none']),(results['total']/results['dkim_none_spf_fail']),
	(results['total']/results['dkim_invalid_spf_pass']),(results['total']/results['dkim_invalid_spf_none']),(results['total']/results['dkim_invalid_spf_fail'])]

explode = (0,0,0,0,0,0,0,0,0)

pie(fracs, explode=explode, labels=labels, autopct='%1.1f%%', shadow=True)

title('Percentage of messages', bbox={'facecolor':'0.8', 'pad':5})

show()
