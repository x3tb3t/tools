#!/usr/bin/python

import sys
import os

def main():

    if len(sys.argv) > 5:
        skipfile = sys.argv[5]
    else:
        skipfile = ”

    spikese = ‘/pentest/fuzzers/spike/src/generic_send_tcp’
    ip = sys.argv[1]
    port = sys.argv[2]
    skipvar = sys.argv[3]
    skipstr = sys.argv[4]

    os.chdir(“vulnserver”)
    allFiles = os.listdir(“.”)
    allFiles.sort()
    for files in allFiles:
        if files.endswith(“.spk”) and files != skipfile:
            cmd = “%s %s %s %s %s %s” % (spikese, ip, port, files, skipvar, skipstr)
        if os.system(cmd):
            print “Stopping processing file %s” % files
            sys.exit(0)

if __name__ == “__main__”:
    main()
