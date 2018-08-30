#!/usr/bin/python2.7

import re
import requests
import urlparse
from bs4 import BeautifulSoup
import tldextract
from modules import settings

# Function to retrieve links from URL
# Look for <a>, <link>, <script> and <iframe> tags and extract href and src from them
def linksFinder(url):

    # can improve for the case /page8.html and ///////page8.html cause both links to page8.html but both will be stored in the url list
    #domainLinksRegex = re.compile('^(https?://' + settings.domain + ')|([a-zA-Z0-9]/?)+(.html|.js|.php|.css)$')
    #domainLinksRegex = re.compile('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    #regexJs = re.compile('^(https?://[a-zA-Z0-9]/?)+(.html|.js|.php|.css)$')

    try:
        r = requests.get(url)
        page = r.text
        soup = BeautifulSoup(page, "html.parser")

        if '.js' in url:
            urlList = re.findall('(?:http://)[^"\' ]+', page)
            
            for link in urlList:
                if settings.domainUrlsRegex.search(link) and link not in settings.targetUrls:
                    print link
                    settings.targetUrls.append(link)

        for htmlTag in settings.htmlTags:

            #for tag in soup.findAll(htmlTag, href=domainLinksRegex):
            for tag in soup.findAll(htmlTag, href=True):
                #print tag
                link = urlparse.urljoin(url, tag['href'])
                #print tag['href']
                if settings.domainUrlsRegex.search(link) and link not in settings.targetUrls:
                    #print url + ' ==> ' + link
                    print link
                    settings.targetUrls.append(link)

            #for tag in soup.findAll(htmlTag, src=domainLinksRegex):
            for tag in soup.findAll(htmlTag, src=True):
                #print tag
                link = urlparse.urljoin(url, tag['src'])
                #print tag['src']
                if settings.domainUrlsRegex.search(link) and link not in settings.targetUrls:
                    #print url + ' ==> ' + link
                    print link
                    settings.targetUrls.append(link)


    except requests.exceptions.ConnectionError:
        #print url + ' : Connection error from linksFinder()'
        return
        #settings.urls.remove(url)

    except requests.exceptions.Timeout:
        # Maybe set up for a retry, or continue in a retry loop
        print 'Request timeout, will retry 3 times : ' + url
        #time.sleep(1)
        #retryCount += 1
        #if retryCount == 3:
        #    pass
        #else:
        #    return linksFinder(url)
    
    except requests.exceptions.TooManyRedirects:
        # Tell the user their URL was bad and try a different one
        print 'Too many redirects : ' + url
    
    except requests.exceptions.RequestException as e:
        print 'Request exception : ' + str(e)
    
    except:
        print url + ' : Error in linksFinder : ' + url



        '''
        # Retrieve src tag from <script>
        for tag in soup.findAll('script', src=True):
            #print tag
            link = urlparse.urljoin(url, tag['src'])
            if settings.domain in link and link not in settings.targetUrls:
                print url + ' ==> ' + link
                settings.targetUrls.append(link)

        # Retrieve href tag from <script>
        for tag in soup.findAll('script', href=True):
            #print tag
            link = urlparse.urljoin(url, tag['href'])
            if settings.domain in link and link not in settings.targetUrls:
                print url + ' ==> ' + link
                settings.targetUrls.append(link)

        # Retrieve href tag from <link>
        for tag in soup.findAll('link', href=True):
            link = urlparse.urljoin(url, tag['href'])
            if settings.domain in link and link not in settings.targetUrls:
                print url + ' ==> ' + link
                settings.targetUrls.append(link)

        # Retrieve src tag from <link>
        for tag in soup.findAll('link', src=True):
            link = urlparse.urljoin(url, tag['src'])
            if settings.domain in link and link not in settings.targetUrls:
                print url + ' ==> ' + link
                settings.targetUrls.append(link)                 

        # Retrieve href tag from <iframe>
        for tag in soup.findAll('iframe', href=True):
            link = urlparse.urljoin(url, tag['href'])
            if settings.domain in link and link not in settings.targetUrls:
                print url + ' ==> ' + link
                settings.targetUrls.append(link)

        # Retrieve src tag from <iframe>
        for tag in soup.findAll('iframe', src=True):
            link = urlparse.urljoin(url, tag['src'])
            if settings.domain in link and link not in settings.targetUrls:
                print url + ' ==> ' + link
                settings.targetUrls.append(link)
'''

            
# Take a list of urls as input and crawl each one to find more links and add them to urls list
def crawlUrls(urls_list):
    for url in urls_list:
        #print url
        linksFinder(url)

        f = open('output/' + settings.domain + '_crawled_urls.txt', 'w')
        for url in settings.targetUrls:
            f.write(url.encode('utf-8') + '\n')
        f.close()


