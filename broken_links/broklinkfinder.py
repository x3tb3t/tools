#!/usr/bin/python2.7

import sys
import argparse
import re
import requests
import urlparse
from bs4 import BeautifulSoup
from modules import settings
from modules import crawler
from modules import domain_available

# init global variables
settings.init()

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Domain to crawl")
    parser.add_argument("-p", "--proto", help="Specify http or https")
    parser.add_argument("-if", "--infile", help="Specify a file with URL to check if domain is registrable")
    return parser.parse_args() 

settings.domain = arg_parser().domain
settings.domainUrlsRegex = re.compile('^https?://' + settings.domain)

if arg_parser().proto:
  if arg_parser().proto == 'http':
    settings.baseUrl = 'http://' + settings.domain
  if arg_parser().proto == 'https':
    settings.baseUrl = 'https://' + settings.domain

if arg_parser().infile:
    with open(arg_parser().infile) as f:
        targetUrls = f.read().splitlines()
    
    for url in targetUrls:
        domain_available.brokenLinks(url)
    sys.exit()

#print 'BaseUrl:\t' + settings.baseUrl 

print '\nAll URLs\n========'
crawler.linksFinder(settings.baseUrl)
crawler.crawlUrls(settings.targetUrls)

print '\nBroken links\n============'
for url in settings.targetUrls:
  domain_available.brokenLinks(url)
print '\n'



