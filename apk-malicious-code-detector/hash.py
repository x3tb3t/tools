import os, glob
from itertools import chain
import hashlib
 
hasher = hashlib.md5()

def hashFiles(path, dict):
	files_lst = []
  
	# Get the file list recursivly from path
	for root, dirs, files in os.walk(path, topdown=False):
		for name in files:
			file = os.path.join(root, name)
			files_lst.append(file)
		
    files_lst = filter(lambda file: not file.endswith('.png'), files_lst)

	# hash all files (except png) and add them to dictionary
	for file in files_lst:
		file_short = file.split('/')[2:]
		file_short = '/'.join(file_short)
		
    with open(file, 'rb') as afile:
			buf = afile.read()
    		hasher = hashlib.sha256()
    		hasher.update(buf)
		
    dict[file_short] = hasher.hexdigest() 
