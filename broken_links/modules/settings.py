# settings.py

def init():
    global domain
    domain = ''

    global baseUrl
    baseUrl = ''

    global domainUrlsRegex
    domainUrlsRegex = ''

    global targetUrls
    targetUrls = []

    global htmlTags
    htmlTags = ['a','link','script','iframe'] 

    global extHost
    extHost = []

    global brokenLinks
    brokenLinks = {}

'''
  # Regex for any http/https links
    global httpLinksRegex
    httpLinksRegex = re.compile('^https?://')

  # Regex for http/https links in the targeted domain
    global domainLinksRegex
    domainLinksRegex = re.compile('^https?://' + domain)

    # Rgex for relative links
    #global relativeLinksRegex
    #relativeLinksRegex = re.compile('^[a-z]|[A-Z]|[0-9]')

'''    