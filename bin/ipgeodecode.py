"""
IPv4 Whois Geodecoding analysis tool

Usage:
    ./ipgeodecode.py ip_address
    ./ipgeodecode.py test
    ./ipgeodecode.py (-h | --help)

Options:
    -h, --help         Show this screen and exit.

Examples:

    ./ipgeodecode.py 127.0.0.1

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

# Used by ip2address
from ipwhois import IPWhois
from pprint import pprint
from datetime import datetime

# Used by address2geoloc
from geopy.geocoders import Nominatim
from geopy.distance import vincenty

# Used by googleGeodecode
import urllib
import json

import logging

def loginfo(app='default',msg=''):
	logging.info("%s >> INFO: %s" % (app, msg))

def logwarning(app='default',msg=''):
	logging.info("%s >> WARNING: %s" % (app, msg))

def logerror(app='default',msg=''):
	logging.info("%s >> ERROR: %s" % (app, msg))


class IPGeoDecode(object):
	"""
	# Two entry point to get an address
	# OpenStreetMap and IPWhois
	# 
	"""
	def __init__(self):
		# Consider Google API as our ground truth
		# knowing that availabiliy may be compromised for various reasons
		self.GOOGLE_GEOCODE_API = 'http://maps.googleapis.com/maps/api/geocode/'
		self.GOOGLE_ZERO_RESULTS = 'ZERO_RESULTS'
		self.GOOGLE_OK = 'OK'
		self.GOOGLE_OVER_QUERY_LIMIT = 'OVER_QUERY_LIMIT'
		self.CAN_USE_GOOGLE_API = True
		self.APP_NAME = 'IPGeoDecode'
		self.GeoLocator = Nominatim()

		logging.basicConfig(filename='ipgeodecode.log', level=logging.INFO, \
							format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


	"""
	###########
	# IPWhois #
	###########
	"""

	"""
	# Returns an address corresponding to the specified IP
	# using the IPWhois library
	"""
	def requestIPWhois(self, ip):
		obj = IPWhois(ip)
		results = obj.lookup()
		return results

	def getAddressFromIPWhois(self,results):
		most_recent_entry = None
		if 'nets' in results:
			if len(results['nets']) == 0:
				logwarning(self.APP_NAME, "IPWhois found no entry for the requested IP %s" % ip)
				raise ValueError("IPWhois found no entry for the requested IP %s" % ip)
			
			elif len(results['nets']) >= 1:
				try:
					# @WARN: We're assuming the entry is present and well formatted
					most_recent_entry = results['nets'][0]
					most_recent_date = self.utcTimeString2DateTime(most_recent_entry['updated'])
					for i, entry in enumerate(results['nets'],1):
						entry_date = self.utcTimeString2DateTime(entry['updated'])
						if entry_date > most_recent_date:
							most_recent_entry = entry
							most_recent_date = entry_date
				
				except Exception:
					logwarning(self.APP_NAME, 'Catched an error while parsin IPWhois entry')
		
		return most_recent_entry

	"""
	# Returns an address corresponding to the specified IP
	# Address is essential
	# Others are concatenated for further precision
	#
	"""
	def entry2address(self, entry):
		address = self.getFieldFromEntry(entry,'address')
		if address:
			address = address.replace('\n',', ')
			if 'city' in entry and entry['city']:
				address += ', ' + entry['city'].replace('\n',', ')
			if 'state' in entry and entry['state']:
				address += ', ' + entry['state'].replace('\n',', ')
		return address

	def getISPFromIPWhois(self,entry):
		if 'asn_registry' in entry:
			return entry['asn_registry']
		else:
			return None

	def getOrganizationFromIPWhois(self,entry):
		if 'description' in entry:
			return entry['description']
		else:
			return None

	def getFieldFromEntry(self,entry,field):
		if field in entry:
			return entry[field]
		else:
			return None

	"""
	# Try to find the organization and use that as the search seed
	# 
	
	def requestWhoIs(self, ip):
		# Scrape website to get a corresponding organization
		url = 'http://whois.arin.net/rest/nets;q=212.249.11.140?showDetails=true&showARIN=false&showNonArinTopLevelNet=false&ext=netref2'
		#response = urllib.urlopen(url).read()

		# Scape organization to get address
	"""

	
	

	"""
	####################
	# Open Street Maps #
	####################
	"""
	def address2geoloc(self, address):
		location = self.GeoLocator.geocode(address)



	"""
	####################
	# Google Geodecode #
	####################
	"""

	"""
	# Returns a URL to query Google Geodecode for a specific address
	# 
	"""
	def buildGoogleGeodecodeURL(self, address, output='json'):
		return self.GOOGLE_GEOCODE_API + output + "?" + "address='" + address + "'"

	"""
	# Returns an address corresponding to the specified IP
	# 
	"""
	def requestGoogleGeodecode(self, address, output='json'):
		url = self.buildGoogleGeodecodeURL(address, output)
		try:
			maximum_attempts_is_not_reached = 3
			success = False
			result = None

			while not success and maximum_attempts_is_not_reached:
				
				loginfo(self.APP_NAME, 'Sending Google Geodecode request url: %s' % url)
				raw_result = urllib.urlopen(url).read()
				maximum_attempts_is_not_reached -= 1

				jsonified_response = json.loads(raw_result)
				request_status = jsonified_response['status']
				result_count = len(jsonified_response['results'])

				if request_status == self.GOOGLE_OK and result_count:				
					result = jsonified_response['results']
					if result_count > 1:
						logwarning(self.APP_NAME, 'More than one Google Geodecode entry found for address %s' % address)
						logwarning(self.APP_NAME, 'Chosing the first Google Geodecode entry')
						result = jsonified_response['results'][0]
					success = True
					
				elif request_status == self.GOOGLE_ZERO_RESULTS:
					raise ValueError("No Google Geodecode entry found for address %s" % address)

				elif request_status == self.GOOGLE_OVER_QUERY_LIMIT:
					self.CAN_USE_GOOGLE_API = False
					logerror(self.APP_NAME, 'Reached maximum Google query limit. Quality of location may degrade')

			if not success:
				logerror(self.APP_NAME, 'Could not retrieve address using Google Geodecode')

			return result[0]

		except Exception:
			print 'IPGeoDecoding >> ERROR: Could not reach Google Geocode API'

	def getLngLatFromGoogleResult(self,result):
		lng = result['geometry']['location']['lng']
		lat = result['geometry']['location']['lat']
		return [lng,lat]



	"""
	#####################
	# Utility Functions #
	#####################
	"""

	"""
	# Returns an address corresponding to the specified IP
	# 
	"""
	def utcTimeString2DateTime(self, utc):
		return datetime.strptime(utc,'%Y-%m-%dT%H:%M:%S')
	
"""
ip = '212.249.11.140'
#ip = '108.223.242.32'
#ip = '207.141.67.177'
geodecode = IPGeoDecode()
entry = geodecode.requestIPWhois(ip)
address_data = geodecode.getAddressFromIPWhois(entry)
address = geodecode.entry2address(address_data)
#googleapi = geodecode.requestGoogleGeodecode(address)
geoloc = geodecode.address2geoloc(address)
"""

import sys
import unittest
from docopt import docopt

class IPGeoDecodeTest(unittest.TestCase):

	def test(self):
		geodecode = IPGeoDecode()
		entry = geodecode.requestIPWhois(opt['ip'])
		address_data = geodecode.getAddressFromIPWhois(entry)
		address = geodecode.entry2address(address_data)
		geoloc = geodecode.address2geoloc(address)
		self.assertEqual(geoloc,[1,0])


def main(argv):

	opt = docopt(__doc__, argv)
	
	geodecode = IPGeoDecode()
	entry = geodecode.requestIPWhois(opt['ip'])
	address_data = geodecode.getAddressFromIPWhois(entry)
	address = geodecode.entry2address(address_data)
	geoloc = geodecode.address2geoloc(address)
	# Nicely print output 


if __name__ == "__main__":
	try:
		#main(sys.argv[1:])
		unittest.main()
	except KeyboardInterrupt:
		pass
