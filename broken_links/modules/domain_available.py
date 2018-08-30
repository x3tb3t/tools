#!/usr/bin/python2.7

import requests
import re
import subprocess
import tldextract
from bs4 import BeautifulSoup
from modules import settings
from time import sleep


# check on www.checkdomain.com
def checkRegistration(url,tld):

    #site = 'http://www.checkdomain.com/cgi-bin/checkdomain.pl?domain=' + tld
    site = 'https://sg.godaddy.com/dpp/find?checkAvail=1&tmskey=&domainToCheck=' + tld
        
    try:
        f = open('output/' + settings.domain + '_broken_links.txt', 'w')

        r = requests.get(site + tld)
        page = r.text
        registered = re.compile(tld + ' is taken')
        unregistered = re.compile('Yes! Your domain is available')
        #registered = re.compile('has already been registered by the organization below')
        #unregistered = re.compile('is still available!')
        if registered.search(page):
            print '%s is not registrable\n' % (tld)
        elif unregistered.search(page):
            print url + ' ==> \033[1m%s is registrable \033[0m \n' % (tld)
            f.write(url + ' ==> \033[1m' + tld + ' is registrable \033[0m \n')
        else:
            print '%s Failed to check if registrable\n' % (tld)

        f.close()

                
    except requests.exceptions.ConnectionError:
        print 'Connection error to www.checkdomain.com for : ' + url
    
    except requests.exceptions.Timeout:
        # Maybe set up for a retry, or continue in a retry loop
        print 'Request timeout, will retry 3 times : ' + url

    except requests.exceptions.RequestException as e:
        print 'Request exception : ' + str(e)
    
    except:
        print url + ' : Error in brokenLinks requesting www.checkdomain.com'


# Find broken links
def brokenLinks(url):
    hosts = []
    # Regex for any http/https links
    httpLinksRegex = re.compile('^https?://')

    try:
        r = requests.get(url)
        page = r.text
        soup = BeautifulSoup(page, "html.parser")

        if '.js' in url:
            urlList = re.findall('(?:https?://)[^"\' ]+', page)
            
            for link in urlList:
                p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
                m = re.search(p, link)
                host = m.group('host')

                if not settings.domain in host:
                    hosts.append(host)

        for htmlTag in settings.htmlTags:
                
            for tag in soup.findAll(htmlTag, href=httpLinksRegex):
                p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
                m = re.search(p, tag['href'])
                host = m.group('host')

                if not settings.domain in host:
                    hosts.append(host)

            for tag in soup.findAll(htmlTag, src=httpLinksRegex):
                p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
                m = re.search(p, tag['src'])
                host = m.group('host')

                if not settings.domain in host:
                    hosts.append(host)                        

    except requests.exceptions.ConnectionError:
        print 'Connection error from brokenLinks() : ' + url
    
    except requests.exceptions.Timeout:
        # Maybe set up for a retry, or continue in a retry loop
        print 'Request timeout, will retry 3 times : ' + url

    except requests.exceptions.TooManyRedirects:
        # Tell the user their URL was bad and try a different one
        print 'Too many redirects : ' + url
    
    except requests.exceptions.RequestException as e:
        print 'Request exception : ' + str(e)
    
    except:
        print url + ' : Error in brokenLinks'


    for host in hosts:
        extracted = tldextract.extract(host)
        tld = "{}.{}".format(extracted.domain, extracted.suffix)

#        checkRegistration(url,tld)

        # check with whois
        cmd = 'whois ' + tld

        sleep(0.1) # Too many requests lead to incorrect responses
        
        try:
            result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")
            if 'Not Found' in result or 'NOT FOUND' in result or 'No match' in result or 'No entries found' in result or 'do not have an entry' in result or 'does not exist' in result or 'nodename nor servname provided' in result:
                print 'URL: ' + url + ' contains broken link: ' + tld
                with open('output/' + settings.domain + '_broken_links.txt', 'w') as f:
                    f.write(url + ' contains broken link: ' + tld)
        except:
            print 'Error in whois : ' + host

