#!/usr/bin/env python

from time import sleep
import sys
'''
try:
	import whois
except ImportError:
	print("ERROR: This script requires the python-whois module to run.")
	print("   You can install it via 'pip install python-whois'")
	sys.exit(0)
'''

import whois

domain = whois.query('google.com')

'''
domains = ['www.graaaaaaaaab.com','frfrfdkjhsdkjdhsd.fr','adaeraerfefafef.com','123dssdsfsf.cn','kjhasdlaop.com.sg','wewqasdadsasdasdasoidadasd21324234.com','tatatatatatatatatatatatatata.my']

for domain in domains:
	sleep(0.5) # Too many requests lead to incorrect responses
	print(' Checking: ' + domain), # Comma means no newline is printed
	print(domain.__dict__)
'''

'''		print('\tTAKEN')
	except whois.parser.PywhoisError:
		# Exception means that the domain is free
		print('\tFREE')
		f = open('free-domains.txt', 'a')
		f.write(domain + '\n')
		f.close()
print("DONE!")
'''