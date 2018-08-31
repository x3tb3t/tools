#!/usr/bin/python

import sys

def usage():
	print """python %s command_file

command_file must contain the commands to fuzz (1 per line).""" % (sys.argv[0])

commands = sys.argv[1]
realCOUNTER = 1

with open(commands) as files:
	for line in files:
		COUNTER = "%02d" % realCOUNTER
		line = line.rstrip().upper()
		lcline = line.rstrip().lower()

		with open(str(COUNTER) + lcline + ".spk", "a") as newfile:
			
			# for ftp authenticated commands
			newfile.write('printf("%s %s%s.spk : ") // Print to window command and file\n' % (line, COUNTER, lcline))
			newfile.write('s_readline(); // Print received line from server\n')

			newfile.write('s_string("USER"); // Send username\n')
			newfile.write('s_string(" "); // Send username\n')
			newfile.write('s_string("anonymous"); // Send username\n')
			newfile.write('s_string("\\r\\n"); // Send username\n')
			newfile.write('s_readline(); // Print received line from server\n')
			newfile.write('s_string("PASS "); // Send pass\n')
			newfile.write('s_string("anonymous"); // Send pass\n')
			newfile.write('s_string("\\r\\n"); // Send pass\n')
			newfile.write('s_readline(); // Print received line from server\n')

			newfile.write('s_string("%s "); // Send "%s " to program\n' % (line, line))
			newfile.write('s_string_variable("COMMAND"); // Send fuzzed string\n')

			# for non authent fuzzing
			#newfile.write('printf("%s %s%s.spk : ") // Print to window command and file\n' % (line, COUNTER, lcline))
			#newfile.write('s_readline(); // Print received line from server\n')
			#newfile.write('s_string("%s "); // Send "%s " to program\n' % (line, line))
			#newfile.write('s_string_variable("COMMAND"); // Send fuzzed string\n')

		realCOUNTER += 1
