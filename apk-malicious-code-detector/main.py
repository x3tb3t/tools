#!/usr/bin/python2

import decompile
import hash
import diff
import argparse

def msg():
	print 'Usage!'

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--malicious", help="Malicious apk")
    parser.add_argument("-o", "--original", help="Original apk")
    parser.add_argument('-u', "--update", help='Update the offline db')
    return parser.parse_args()


if arg_parser().update == 'all':
    list_url = fetch.geturls()
    print list_url

	
maliciousApp = arg_parser().malicious
originalApp = arg_parser().original

output_path1 = 'output/malicious_app/' 
output_path2 = 'output/legit_app/' 
hash_dict1 = {}
hash_dict2 = {}

print 'Decompile malicious app...'
decompile.disass(maliciousApp, output_path1)

print 'Decompile original app...'
decompile.disass(originalApp, output_path2)

hash.hashFiles(output_path1, hash_dict1)
hash.hashFiles(output_path2, hash_dict2)

for k in hash_dict1:
        if k in hash_dict2:
                if hash_dict1[k] != hash_dict2[k]:
                        print k + " : hashes doesn't match !"
			absolute_file1 = 'output/legit_app/' + k
			absolute_file2 = 'output/malicious_app/' + k
			diff.file_diff(absolute_file1, absolute_file2)
        else:
                print k + " : This file is not present in the original app !"

print 'Export results in HTML files'
