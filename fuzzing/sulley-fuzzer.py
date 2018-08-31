#!/usr/bin/python
 
from sulley import *
import sys
import time
 
""" Receive banner when connecting to server. """
def banner(sock):
    sock.recv(1024)
 
""" Define data model. """
sulley.s_initialize("server.exe")

s_group("commands", values=['USERNAME', 'PASSWORD', 'HELP'])
 
s_block_start("CommandBlock", group="commands")
s_delim(' ')
s_string('fuzz')
s_static('\r\n')
s_block_end()
 
""" Keep session information if we want to resume at a later point. """
s = sessions.session(session_filename="audits/server.session")
 
""" Define state model. """
s.connect(s_get("server.exe"))
 
""" Define the target to fuzz. """
target = sessions.target("192.168.88.105", 1337)
target.netmon = pedrpc.client("192.168.88.105", 26001)
target.procmon = pedrpc.client("192.168.88.105", 26002)
 
target.procmon_options = {
"proc_name" : "server.exe",
"stop_commands" : ['wmic process where (name="server.exe") delete'],
"start_commands" : ['C:\\Users\\alex\\Desktop\\server.exe'],
}
 
""" grab the banner from the server """
s.pre_send = banner
 
""" start fuzzing - define target and data """
s.add_target(target)
s.fuzz()
