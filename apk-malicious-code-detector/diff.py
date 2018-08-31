import sys
import difflib

def file_diff(original_file, malicious_file):
	fromfile = original_file
	tofile = malicious_file
	fromlines = open(fromfile, 'U').readlines()
	tolines = open(tofile, 'U').readlines()

	diff = difflib.HtmlDiff().make_file(fromlines,tolines,fromfile,tofile)
	output_html_file = original_file.replace("/", "-") + '.html'
	diff_report = open(output_html_file, "w")
	diff_report.write(diff)
	diff_report.close()

	
