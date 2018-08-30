import os
import nmap

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

def ping_scan(target):
    os.system('clear')
    banner()
    print '\033[1m\033[31mCurrent target: %s\033[37m\033[0m' % (target)
    print ''
    print '===================================================================='
    print '                        \033[32m  PING SCAN  \033[37m               '
    print '===================================================================='
    ping_scan_args = '-sP'
    print '\033[32m[+] Target:\033[37m %s' % (target)
    print '\033[32m[+] Nmap settings:\033[37m %s' % (ping_scan_args)
    print '\033[32m[*] The scan is in progress...\033[37m'
    print ''

    nm = nmap.PortScanner()
    nm.scan(hosts='%s' % (target), arguments='%s' % (ping_scan_args))

    global ip_victims
    ip_victims = []
    global mac_victims
    mac_victims = []

    try:
        for host in nm.all_hosts():
            # Print all infos available for this host
            #print nm[host]
            print '\033[1m\033[32m[+] \033[37mHost :\033[32m %s %s %s! \033[37mReason:\033[32m %s\033[37m\033[0m' % (host, nm[host].hostname(), str.upper(nm[host].state()), str.upper(nm[host]['status']['reason']))
            mac_infos = nm[host]['vendor']
            list_mac = []
            for key, value in dict.iteritems(mac_infos):
                temp = [key,value]
                list_mac.append(temp)
            try:
                print 'Mac address          : %s' % (list_mac[0][0])
                print 'Mac address vendor   : %s' % (list_mac[0][1])
                print ''
                print '===================================================================='
                ip_victims.append(host)
                mac_victims.append(list_mac[0][0])
            except:
                print '\033[31m[-] No more informations found for this host. Passing to the next one.\033[37m'
                print ''
                pass
    except:
        print '\033[31m[-] No more informations found for this host. Passing to the next one.\033[37m'
        print ''
        pass
    
    print '\033[31mScan finished.\033[37m'


def port_scan(target):
    os.system('clear')
    banner()
    print '\033[1m\033[31mCurrent target: %s\033[37m\033[0m' % (target)
    print ''
    print '===================================================================='
    print '                        \033[32m  PORT SCAN  \033[37m               '
    print '===================================================================='
    port_scan_args = '-sV -p 1-1024'
    print '\033[32m[+] Target:\033[37m %s' % (target)
    print '\033[32m[+] Nmap settings:\033[37m %s' % (port_scan_args)
    print '\033[32m[*] The scan is in progress...\033[37m'
    print '\033[31m[*] Port scan may take a long time, be patient :)\033[37m'
    print ''

    nm = nmap.PortScanner()
    nm.scan(hosts='%s' % (target), arguments='%s' % (port_scan_args))

    global ip_victims
    ip_victims = []
    global mac_victims
    mac_victims = []

    try:
        for host in nm.all_hosts():
            # Print all infos available for this host
            #print nm[host]
            print '\033[1m\033[32m[+] \033[37mHost :\033[32m %s %s %s! \033[37mReason:\033[32m %s\033[37m\033[0m' % (host, nm[host].hostname(), str.upper(nm[host].state()), str.upper(nm[host]['status']['reason']))
            mac_infos = nm[host]['vendor']
            list_mac = []
            for key, value in dict.iteritems(mac_infos):
                temp = [key,value]
                list_mac.append(temp)
            try:
                print 'Mac address          : %s' % (list_mac[0][0])
                print 'Mac address vendor   : %s' % (list_mac[0][1])
                for proto in nm[host].all_protocols():
                    print '' 
                    lport = nm[host][proto].keys()
                    lport.sort()
                    print '\033[1mProto\tPort\tState  \tVersion\tService\033[0m'
                    for port in lport:
                        print '\033[32m%s\t%s\t%s  \t%s\t%s\033[37m' % (proto, port, nm[host][proto][port]['state'], nm[host][proto][port]['version'], nm[host][proto][port]['product'])
                print ''
                print '===================================================================='
                ip_victims.append(host)
                mac_victims.append(list_mac[0][0])
            except:
                print '\033[31m[-] No more informations found for this host. Passing to the next one.\033[37m'
                print ''
                pass
    except:
        print '\033[31m[-] No more informations found for this host. Passing to the next one.\033[37m'
        print ''
        pass
    
    print '\033[31mScan finished.\033[37m'


def os_scan(target):
    os.system('clear')
    banner()
    print '\033[1m\033[31mCurrent target: %s\033[37m\033[0m' % (target)
    print ''
    print '===================================================================='
    print '                          \033[32m  OS SCAN  \033[37m               '
    print '===================================================================='
    os_scan_args = '-O --osscan-guess'
    print '\033[32m[+] Target:\033[37m %s' % (target)
    print '\033[32m[+] Nmap settings:\033[37m %s' % (os_scan_args)
    print '\033[32m[*] The scan is in progress...\033[37m'
    print '\033[31m[*] OS scan may take a long time, be patient :)\033[37m'
    print ''

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts='%s' % (target), arguments='%s' % (os_scan_args))
    except:
        print '\033[31m[-] Scan error.\033[37m'

    global ip_victims
    ip_victims = []
    global mac_victims
    mac_victims = []

    #print nm.all_hosts()
    try:
        for host in nm.all_hosts():
            print '\033[1m\033[32m[+] \033[37mHost :\033[32m %s %s %s! \033[37mReason:\033[32m %s\033[37m\033[0m' % (host, nm[host].hostname(), str.upper(nm[host].state()), str.upper(nm[host]['status']['reason']))
            mac_infos = nm[host]['vendor']
            list_mac = []
            for key, value in dict.iteritems(mac_infos):
                temp = [key,value]
                list_mac.append(temp)
            try:
                #print nm[host]
                print 'Mac address          : %s' % (list_mac[0][0])
                print 'Mac address vendor   : %s' % (list_mac[0][1])
                print '--------------------------------------------------'
                print 'OS           : %s' % (nm[host]['osclass']['osfamily'])
                print 'Family       : %s' % (nm[host]['osclass']['vendor'])
                print 'Type         : %s' % (nm[host]['osclass']['type'])
                print 'OS Gen       : %s' % (nm[host]['osclass']['osgen'])
                print 'Accuracy     : %s' % (nm[host]['osclass']['accuracy'])
                print ''
                print '===================================================================='
                ip_victims.append(host)
                mac_victims.append(list_mac[0][0])
            except:
                print '\033[31m[-] No more informations found for this host. Passing to the next one.\033[37m'
                print ''
                pass
    except:
         print '\033[31m[-] No more informations found for this host. Passing to the next one.\033[37m'
         print ''
         pass

    print '\033[31mScan finished.\033[37m'
            # Print all infos available for this host
            #print nm[host]
            #print nm[host]['tcp']
            #print ce qui est disponible dans osclass
            #print(nm[host]['osclass'])


def custom_scan(target, args):
    os.system('clear')
    banner()
    print '\033[1m\033[31mCurrent target: %s\033[37m\033[0m' % (target)
    print ''
    print '===================================================================='
    print '                      \033[32m  CUSTOM SCAN  \033[37m               '
    print '===================================================================='
    print '\033[32m[+] Target:\033[37m %s' % (target)
    print '\033[32m[+] Nmap settings:\033[37m %s' % (args)
    print '\033[32m[*] The scan is in progress...\033[37m'
    print ''

    nm = nmap.PortScanner()
    nm.scan(hosts='%s' % (target), arguments='%s' % (args))

    global ip_victims
    ip_victims = []
    global mac_victims
    mac_victims = []

    try:
        for host in nm.all_hosts():
            # Print all infos available for this host
            #print nm[host]
            print '\033[1m\033[32m[+] \033[37mHost :\033[32m %s %s %s! \033[37mReason:\033[32m %s\033[37m\033[0m' % (host, nm[host].hostname(), str.upper(nm[host].state()), str.upper(nm[host]['status']['reason']))
            mac_infos = nm[host]['vendor']
            list_mac = []
            for key, value in dict.iteritems(mac_infos):
                temp = [key,value]
                list_mac.append(temp)
            try:
                print 'Mac address          : %s' % (list_mac[0][0])
                print 'Mac address vendor   : %s' % (list_mac[0][1])
                print ''
                print '===================================================================='
                ip_victims.append(host)
                mac_victims.append(list_mac[0][0])
            except:
                print '\033[31m[-] No more informations found for this host. Passing to the next one.\033[37m'
                print ''
                pass
    except:
        print '\033[31m[-] No more informations found for this host. Passing to the next one.\033[37m'
        print ''
        pass
    
    print '\033[31mScan finished.\033[37m'
