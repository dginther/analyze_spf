# DKIM analyzer
# Author: Demian Ginther (demian@atpay.com)

import dkim
import os
import email.utils
import re

results = {'valid': 0, 'invalid': 0, 'total': 0}

path = 'emails/'

listing = os.listdir(path)

for infile in listing:
  try:
    with open(path + infile) as f:
      msg = f.read()
      #print(msg)
      m = re.compile("From:.+")
      from_address = re.search("From: (.+)", msg).group(1)
      if "<" in from_address or ">" in from_address:
        from_address = re.search("<(.+)>", from_address).group(1)
      #print(from_address)
      try:
        result = dkim.verify(msg)
      except DKIMException as x:
        print('DKIM Exception: ' + str(x))
      results[str(from_address)] = str(result)
      results['total'] += 1
      if result == True:
        results['valid'] += 1
      else:
        results['invalid'] += 1
  except IOError as ioerr:
    print('IO Error: ' + str(ioerr))

print("Results: ")
print("Total records: " + str(results['total']))
print("Valid DKIM: " + str(results['valid']))
print("Invalid or no DKIM: " + str(results['invalid']))
print(results)
