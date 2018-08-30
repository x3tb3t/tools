#!/usr/bin/python
# Filename: net_infos.py

'''

This module is useful to get network infos of the current subnet.

'''

import sys
import netifaces
import netaddr
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

import arp_spoof


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

try:
    gateways = netifaces.gateways()
    iface = gateways['default'][2][1]
    global default_gw
    default_gw = gateways['default'][netifaces.AF_INET][0]
    my_ip = netifaces.ifaddresses(iface)[2][0]['addr']
    my_mac = get_if_hwaddr(iface)
    netmask = netifaces.ifaddresses(iface)[2][0]['netmask']
    broadcast = netifaces.ifaddresses(iface)[2][0]['broadcast']
except Exception as e:
    print str(e) + '.' '\033[31mPlease check your internet connection!\033[37m'
    sys.exit(1)

try:
    # resolve default gateway mac address
    global gw_mac_address
    gw_mac_address = arp_spoof.origin_mac(default_gw)

    # Network CIDR address and Network range
    my_ip_format = netaddr.IPAddress(my_ip)
    network_mask = netaddr.IPAddress(netmask)
    network_addr = my_ip_format & network_mask
    global cidr_addr
    cidr_addr = netaddr.IPNetwork(str(network_addr) + '/' + str(network_mask))
    net_range = netaddr.IPRange(cidr_addr[1], cidr_addr[-2])
except Exception as e:
    print str(e) + '.' '\033[31mError!\033[37m'
    sys.exit(1)

def get_net_infos():
    banner()
    set_target(cidr_addr)

    print '===================================================================='
    print '                      \033[32m  Your informations  \033[37m         '
    print '===================================================================='
    print ' Default interface              : ' + iface
    print ' MAC address                    : ' + my_mac
    print ' IP address                     : ' + my_ip
    print ' Netmask                        : ' + netmask
    print ''
    print '===================================================================='
    print '                        \033[32m  Network infos  \033[37m           '
    print '===================================================================='
    print ' Network address (CIDR)         : ' + str(cidr_addr)
    print ' Gateway IP address             : ' + default_gw
    print ' Gateway MAC address            : ' + gw_mac_address
    print ' Broadcast                      : ' + broadcast
    print ' Network range                  : ' + str(net_range)
    print ''