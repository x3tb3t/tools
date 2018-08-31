#!/usr/bin/python

# api tester
# authentication
# authorisation (idor)
# rate limiting (bruteforce/enumeration)
# injections

import requests

# Endpoint list: find accurate way to get all api endpoints or have to hardcode it.
endpoints = {'api.host.com':['/api/test/v1/client', '/test1', '/test2'], 'api2.host.com':['/test1', '/test2'], 'api3.host.com':['/test1', '/test2']}

# Sample data
authTokens = ['', '', '']
clientId = ['', '', '']
clientName = ['', '', '']
storeId = ['', '', '']
storeName = ['', '', '']
productId = ['', '', '']
productName = ['', '', '']
productType = ['', '', '']
phoneNumbers = ['', '', '']
postalAddresses = ['', '', '']

# Payloads
sqliPayloads = ['', '', '']
nosqliPayloads = ['', '', '']

unAuthenticatedEndpoints = []

def doReport():
	print '\n======\nReport\n======\n'
	print 'UnAuthenticated endpoints\n========================'
	for endpoint in unAuthenticatedEndpoints:
		print endpoint


def whichProto(host, proto):
	url = proto + '://' + host + '/idonotexist123Test'

	try:
		r = requests.get(url, timeout=10)

		statusCode = r.status_code
		if statusCode == 404:
			print '\t[*] This host listen on ' + proto
			return 1
		else:
			print '[-] Not able to detect if host is listening on ' + proto
			return 'error'

	except requests.exceptions.Timeout, e:
		print '\t[*] This host don\'t listen on ' + proto
 		return 0

def isValidEndpoint(url):
	try:
		r = requests.get(url, timeout=10)
		statusCode = r.status_code
		if statusCode == 403 or statusCode == 200:
			print '\t[*] Endpoint is valid : ' + url
			return 1
		else:
			print '\t[-] Endpoint is not valid: (' + str(statusCode) + ') : ' + url
			return -1

	except requests.exceptions.Timeout, e:
		print '\t[-] Endpoint is not valid (TIMEOUT) : ' + url
		return -1

	# test GET

	# test POST

	# test PUT

	# test DELETE

	# test TRACE

	# test OPTIONS


# test accessible without authentication
def isAuthenticated(url):
	print '[*] isAuthenticated(): ' + url

	try:
		r = requests.get(url, timeout=10)
		#if r.text != '':
		#	print '\t' + r.text
		#print r.status_code

		statusCode = r.status_code

		if statusCode == 403:
			print '\t[*] Endpoint is AUTHENTICATED'
			return 'authenticated'
		elif statusCode == 200:
			print '\t[*] Endpoint is NOT AUTHENTICATED'
			unAuthenticatedEndpoints.append(url)
			return 'unauthenticated'
		else:
			print '\t[-] Status code: ' + str(statusCode)
			return 'unknown'

	except requests.exceptions.Timeout, e:
		print '\t[-] Request TIMEOUT'
		return 'timeOut'

def bypassAuth(endpoint):
	# try bypass auth (change HTTP methods, SQLi, NoSQLi)
	print '\t[*] bypassAuth(): not implemented yet'

def idor(endpoint):
	# IDOR (bookingId, driverId, phoneNumbers, etc.)
	print '\tidor(): not implemented yet'	

def sqli(endpoint):
	print '\tsqli(): not implemented yet'	

def nosqli(endpoint):
	print '\tnosqli(): not implemented yet'	

def bruteforce(endpoint):
	print '\tbruteforce(): not implemented yet'	

def finding():
	print '\tfinding(): not implemented yet'	


def main():

	urls = []
	validUrls = []

	statusCode = ''

	print '\nEndpoints list\n=============='
	for host, endpointList in endpoints.iteritems():
		print '[*] ' + host + ' :'
		# look if host is listening on HTTP, HTTPS or both
		isHTTP = whichProto(host, 'http')
		isHTTPS = whichProto(host, 'https')

		for endpoint in endpointList:
			#print host + ': ' + endpoint

			if isHTTP and isHTTPS:
				urls.append('http://' + host + endpoint)
				urls.append('https://' + host + endpoint)
			elif isHTTP:
				urls.append('http://' + host + endpoint)
			elif isHTTPS:
				urls.append('https://' + host + endpoint)
			else:
				pass
	
	print '\n\ncheck endpoints validity\n========================'
	for url in urls:
		if isValidEndpoint(url) != -1:
			validUrls.append(url)

	print '\n\nstart testing endpoints\n======================='
	for validUrl in validUrls:
		statusCode = isAuthenticated(validUrl)
		if statusCode == 'unauthenticated':
			idor(endpoint)
			sqli(endpoint)
			nosqli(endpoint)
			bruteforce(endpoint)
		elif statusCode == 'authenticated':
			bypassAuth(endpoint)
				# if failed, use token
				# else raise finding
		else:
			pass

	doReport()
	

if __name__ == "__main__":
    main()
