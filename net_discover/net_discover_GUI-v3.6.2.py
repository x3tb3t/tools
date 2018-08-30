#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ---------------------------------------------------------#
#                       PRE-REQUISTES                      #
# ---------------------------------------------------------#
# 1 - apt-get install python-nmap                          #
# 2 - apt-get install python-netifaces                     # 
# 3 - apt-get install python-netaddr                       #
# 4 - apt-get install python-tk                            # 
# 5 - apt-get install scapy                                #
# 6 - apt-get install tcpdump 				               #
#                                                          #
# If fall into : 'Check your connection' while you're      # 
# connected, install netifaces from source (v >= 10.0.0)   # 
#                                                          #
# If get an error error with PortScanner or is not         # 
# found, install from source :                             #
#       - tar zxvf python-nmap-0.4.4.tar.gz                #                     
#       - cd python nmap-0.4.4/                            #
#       - python setup.py install                          #
# ---------------------------------------------------------#

try:
    import os
    import sys
    import nmap
    import netifaces
    import modules.net_infos
    import modules.scans
    import modules.find_subnets
    import netaddr
    import Tkinter as tk
    from tkMessageBox import *
    import threading
    import thread
    import signal
    import logging
    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
    from scapy.all import *
    from time import *
except ImportError as e:
    print '%s. Check the pre-requiste first :' % (e)
    print '''
# ---------------------------------------------------------#
#                       PRE-REQUISTES                      #
# ---------------------------------------------------------#
# 1 - apt-get install python-nmap                          #
# 2 - apt-get install python-netifaces                     #
# 3 - apt-get install python-netaddr                       #
# 4 - apt-get install python-tk                            #
# 5 - apt-get install scapy                                #
# 6 - apt-get install tcpdump                              #
#                                                          #
# If fall into : 'Check your connection' while you're      #
# connected, install netifaces from source (v >= 10.0.0)   #
#                                                          #
# If get an error error with PortScanner or is not         #
# found, install from source :                             #
#       - tar zxvf python-nmap-0.4.4.tar.gz                #
#       - cd python nmap-0.4.4/                            #
#       - python setup.py install                          #
# ---------------------------------------------------------#
'''
    sys.exit(1)


# --------------------------------------------------------------------------------------------------- #
#                                                VARIABLES                                            #
# --------------------------------------------------------------------------------------------------- #


global new_target
new_target = ''
global src_ip
src_ip = ''
global src_mac
src_mac = ''
global src_port
src_port = ''
global dst_port
dst_port = ''

global ip_victims 
ip_victims = []
global mac_victims 
mac_victims = []

# --------------------------------------------------------------------------------------------------- #
#                                                FONCTIONS                                            #
# --------------------------------------------------------------------------------------------------- #


# ------------------------------------------- START - DEF GUI --------------------------------------- #

class Page(tk.Frame):
        def __init__(self, *args, **kwargs):
                tk.Frame.__init__(self, *args, **kwargs)
        def show(self):
                self.lift()

class Page1(Page):
    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)
        label_page = tk.Label(self, text='Scan to find hosts, OS, open services and versions.').pack(side='top', fill='both', expand=True)
        
        # Target windows part
        label_window_target = tk.LabelFrame(self, text='Set the target ', padx=15, pady=15)
        label_window_target.pack(fill='both', expand=True)

        label_target = tk.Label(label_window_target, text='Custom:').pack(side='left')
        entry_target = tk.Entry(label_window_target)
        entry_target.pack(side='left')
        lan_target_checkbox = tk.Checkbutton(label_window_target, text='Set the target as LAN (%s):' % (modules.net_infos.cidr_addr), command=set_target(modules.net_infos.cidr_addr)).pack()
        
        # Scan window part
        label_window_scan = tk.LabelFrame(self, text='Start the scan ', padx=15, pady=15)
        label_window_scan.pack(fill='both', expand=True)

        button_wipe_shell = tk.Button(label_window_scan, text='Wipe the shell :)', command=lambda: banner()).pack(side='bottom', fill='both', expand=True)
        button_os_scan = tk.Button(label_window_scan, text='OS Scan', command=lambda: os_scan_clicked()).pack(side='bottom', fill='both', expand=True)
        button_port_scan = tk.Button(label_window_scan, text='Port Scan', command=lambda: port_scan_clicked()).pack(side='bottom', fill='both', expand=True)
        button_ping_scan = tk.Button(label_window_scan, text='Ping Scan', command=lambda: ping_scan_clicked()).pack(side='bottom', fill='both', expand=True)
        button_net_infos = tk.Button(label_window_scan, text='Network Infos', command=lambda: modules.net_infos.get_net_infos()).pack(side='bottom', fill='both', expand=True)
        #button_scan = tk.Button(self, text='Scan the network', command=lambda: threading.Thread(nm_scan(str(cidr_addr)))).pack()

        # When hit Enter set global target to entry value + print it
        #def save_target(event):
        #   global new_target
        #   new_target = entry_target.get()         
        #   print new_target
        #entry_target.bind('<Return>', save_target)

        def ping_scan_clicked():
            if len(entry_target.get()) > 0:
                global new_target
                new_target = entry_target.get()
                modules.scans.ping_scan(new_target)
            else:
                new_target = modules.net_infos.cidr_addr
                modules.scans.ping_scan(new_target)

        def port_scan_clicked():
            if len(entry_target.get()) > 0:
                global new_target
                new_target = entry_target.get()
                modules.scans.port_scan(new_target)
            else:
                new_target = modules.net_infos.cidr_addr
                modules.scans.port_scan(new_target)

        def os_scan_clicked():
            if len(entry_target.get()) > 0:
                global new_target
                new_target = entry_target.get()
                modules.scans.os_scan(new_target)
            else:
                new_target = modules.net_infos.cidr_addr
                modules.scans.os_scan(new_target)


class Page2(Page):
     def __init__(self, *args, **kwargs):
            Page.__init__(self, *args, **kwargs)
            label = tk.Label(self, text='Reachable subnets').pack(side='top', fill='both', expand=True)
            # Scan window part
            label_window_scan = tk.LabelFrame(self, text='Start the scan ', padx=15, pady=15)
            label_window_scan.pack(fill='both', expand=True)
            button_find_subnets = tk.Button(label_window_scan, text='Find subnets', command=lambda: modules.find_subnets.start_find_subnets()).pack(side='bottom', fill='both', expand=True)

class Page3(Page):
     def __init__(self, *args, **kwargs):
             Page.__init__(self, *args, **kwargs)
             label = tk.Label(self, text='Evade Anti-Virus').pack(side='top', fill='both', expand=True)

class Page4(Page):
    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)
        label = tk.Label(self, text='Custom scan').pack(side='top', fill='both')

        label_window_scan = tk.LabelFrame(self, text='Build your scan ', padx=15, pady=15)
        label_window_scan.pack(fill='both')

        label_custom_target = tk.Label(label_window_scan, text='Target:').pack(side='top')
        entry_custom_target = tk.Entry(label_window_scan)
        entry_custom_target.pack(side='top')

        label_custom_src_ip = tk.Label(label_window_scan, text='Source IP:').pack(side='top')
        entry_custom_src_ip = tk.Entry(label_window_scan)
        entry_custom_src_ip.pack(side='top')

        label_custom_src_mac = tk.Label(label_window_scan, text='Source MAC:').pack(side='top')
        entry_custom_src_mac = tk.Entry(label_window_scan)
        entry_custom_src_mac.pack(side='top')

        label_custom_src_port = tk.Label(label_window_scan, text='Source port:').pack(side='top')
        entry_custom_src_port = tk.Entry(label_window_scan)
        entry_custom_src_port.pack(side='top')

        label_custom_dst_port = tk.Label(label_window_scan, text='Destination port:').pack(side='top')
        entry_custom_dst_port = tk.Entry(label_window_scan)
        entry_custom_dst_port.pack(side='top')

        label_custom_nmap_args = tk.Label(label_window_scan, text='Custom nmap options:').pack(side='top')
        entry_custom_nmap_args = tk.Entry(label_window_scan)
        entry_custom_nmap_args.pack(side='top')

        button_ping_scan = tk.Button(self, text='Start the Scan', command=lambda: start_scan_clicked()).pack(side='bottom', fill='both', expand=True)

        def start_scan_clicked():
            scan_args = ''
            if len(entry_custom_target.get()) > 0:
                global new_target
                new_target = entry_custom_target.get()
            if len(entry_custom_src_ip.get()) > 0:
                global src_ip
                src_ip = entry_custom_src_ip.get()
                scan_args = scan_args + ' -S ' + src_ip + ' -e ' + modules.net_infos.iface
            if len(entry_custom_src_mac.get()) > 0:
                global src_mac
                src_mac = entry_custom_src_mac.get()
                scan_args = scan_args + ' --source-mac ' + src_mac
            if len(entry_custom_src_port.get()) > 0:
                global src_port
                src_port = entry_custom_src_port.get()
                scan_args = scan_args + ' --source-port ' + src_port
            if len(entry_custom_dst_port.get()) > 0:
                global dst_port
                dst_port = entry_custom_dst_port.get()
                scan_args = scan_args + ' -p ' + dst_port
            if len(entry_custom_nmap_args.get()) > 0:
                scan_args = scan_args + ' ' + entry_custom_nmap_args.get() 

            modules.scans.custom_scan(new_target, scan_args)

class MainView(tk.Frame):
        def __init__(self, *args, **kwargs):
                tk.Frame.__init__(self, *args, **kwargs)
                p1 = Page1(self)
                p2 = Page2(self)
                p3 = Page3(self)
                p4 = Page4(self)

                buttonframe = tk.Frame(self)
                container = tk.Frame(self)
                buttonframe.pack(side='top', fill='x', expand=False)
                container.pack(side='top', fill='both', expand=True)

                p1.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
                p2.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
                p3.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
                p4.place(in_=container, x=0, y=0, relwidth=1, relheight=1)

                b1 = tk.Button(buttonframe, text='Scan', command=p1.lift).pack(side='left',fill='x', expand=True)
                b2 = tk.Button(buttonframe, text='Routing', command=p2.lift).pack(side='left',fill='x', expand=True)
                b3 = tk.Button(buttonframe, text='Evade FW/IDS/IPS', command=p3.lift).pack(side='left',fill='x', expand=True)
                b4 = tk.Button(buttonframe, text='Custom scan', command=p4.lift).pack(side='left',fill='x', expand=True)
                b5 = tk.Button(buttonframe, text='Close', command=lambda: exit_prog()).pack(side='left',fill='x', expand=True)

                p1.show()

# ------------------------------------------- STOP - DEF GUI ---------------------------------------- #


def banner():
    os.system('clear')
    print ' _   _      _    ______ _                               _____           _ '
    print '| \ | |    | |   |  _  (_)                             |_   _|         | |'
    print '|  \| | ___| |_  | | | |_ ___  ___ _____   _____ _ __    | | ___   ___ | |'
    print '| . ` |/ _ \ __| | | | | / __|/ __/ _ \ \ / / _ \ \'__|   | |/ _ \ / _ \| |'
    print '| |\  |  __/ |_  | |/ /| \__ \ (_| (_) \ V /  __/ |      | | (_) | (_) | |'
    print '\_| \_/\___|\__| |___/ |_|___/\___\___/ \_/ \___|_|      \_/\___/ \___/|_|'
    print ' ______ ______ ______ ______ ______ ______ ______ ______ ______ ______    '
    print '|______|______|______|______|______|______|______|______|______|______|   '
    print ''

def set_target(target):
    global new_target
    new_target = str(target)
    print '\033[1m\033[31mCurrent target: %s\033[37m\033[0m' % (new_target)

def origin_mac(ip):
    ans,unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3, verbose=0)
    for s,r in ans:
        mac = r[Ether].src
        return r[Ether].src



def signal_handler(signal, frame):
    print ''
    print '\033[32mProgram shutdown\033[37m'
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def exit_prog():
    print ''
    print '\033[32mProgram shutdown\033[37m'
    sys.exit(0)

def threadmain():
    # Define and start tkinter GUI
    root = tk.Tk()
    main = MainView(root)
    main.pack(side='top', fill='both', expand=True)
    root.title('Net Discover')
    #root.vm_iconbitmap('app.ico')
    root.wm_geometry('600x450')
    root.mainloop()


# --------------------------------------------------------------------------------------------------- #
#                                                PROGRAM                                              #
# --------------------------------------------------------------------------------------------------- #

if __name__ == '__main__':

    # is the current user, root ?
    if os.getuid() != 0:
        print '\033[31m[-] Please run this program as root\033[37m'
        sys.exit(1)

    modules.net_infos.banner()

    # Start GUI and wait
    try:
        threading.Thread(threadmain())
        while 1:
            sleep(1)
    except:
        sys.exit(0)
