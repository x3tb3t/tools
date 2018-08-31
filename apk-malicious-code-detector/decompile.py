#!/usr/bin/python

import subprocess
import sys
import os

def disass(filename, path):
    command = ['apktool', '--version']

    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    result = p.communicate()[0]

    if "2." not in result:
        print "[-] apktool version 2 is not installed or not in $PATH"
        sys.exit(1)

    print "[*] Decompile app..."
    command = ['apktool', 'd', filename, '-o', path, '-f']

    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    result = p.communicate()[0]

    if 'error' in result:
        print "[-] Decompilation error :\n", result
    else:
        print "[+] Decompilation success"
