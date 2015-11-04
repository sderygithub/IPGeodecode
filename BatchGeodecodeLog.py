"""
Batch Geodecoding log file tool

Usage:

Options:

Examples:

License:

Copyright (c) 2015 Sebastien Dery

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import os
import csv
import logging

import ipgeodecode
import lrucache

#execfile('IPGeoDecode.py')
#execfile('LRUCache.py')

app_name = 'BatchGeodecodeLog.py'

input_fullpath = './access.log.test'
[input_path, input_file] = os.path.split(input_fullpath)

output_file = input_file.replace('.','_') + ".out"
output_fullpath = input_path + '/' + output_file

geodecode = IPGeoDecode()

DEFAULT_NOT_FOUND = '-'

ip_hash = LRUCache(25)

with open(input_fullpath, 'rb') as inputcsv:
	with open(output_fullpath, 'w') as outputcsv:
		# Determine best parsing strategy
		dialect = csv.Sniffer().sniff(inputcsv.read(1024), delimiters=" ;,")
		inputcsv.seek(0)
		reader = csv.reader(inputcsv, dialect)
		# Use the native csv writer to simplify formatting
		writer = csv.writer(outputcsv, delimiter=',')

		for i, line in enumerate(reader):

			if i % 1000 == 0:
				print "Processing log %i" % i

			ip = line[0]
			identify = line[1]
			httpid = line[2]
			date = line[3] + line[4]
			request = line[5]
			statuscode = line[6]
			size = line[7]
			referer = line[8]
			useragent = line[9]

			if ip_hash.keyIn(ip):
				loginfo(app_name,"Known IP (%s), Retrieving geolocation from memory" % ip)
			else:
				print "Unseen IP (%s)" % ip
				loginfo(app_name,"Unseen IP (%s). Requesting geolocation information" % ip)
				
				# Make a Whois request
				entry = geodecode.requestIPWhois(ip)
				address_data = geodecode.getAddressFromIPWhois(entry)
				
				# Get specific Whois data
				isp = geodecode.getISPFromIPWhois(entry)
				if not isp:
					isp = DEFAULT_NOT_FOUND

				longitude, latitude = DEFAULT_NOT_FOUND, DEFAULT_NOT_FOUND
				address = geodecode.entry2address(address_data)
				if address:
					# Request geolocation from Google
					googleapi = geodecode.requestGoogleGeodecode(address)
					if googleapi:
						location = geodecode.getLngLatFromGoogleResult(googleapi)
						if location:
							longitude, latitude = location[0], location[1]							

					# Most often when there is no address, the organization is not reliable
					organization = geodecode.getOrganizationFromIPWhois(address_data)
					if not organization:
						organization = DEFAULT_NOT_FOUND

				ip_hash.set(ip,{'organization': organization, \
								'latitude': latitude, \
								'longitude': longitude, \
								'isp': isp })

			row = [date, referer, ip, ip_hash[ip]['organization'], ip_hash[ip]['latitude'], ip_hash[ip]['longitude'], ip_hash[ip]['isp']]
			writer.writerow(row)
