#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse, shodan, sys, requests, os
from datetime import datetime

SHODAN_API_KEY = ''
hosts = {}

class color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    TITLE = '\033[96m'


def banner():
    print(color.GREEN)
    print('   _____ __              __                        _____                      __  ')
    print('  / ___// /_  ____  ____/ /___  ____              / ___/___  ____  __________/ /_ ')
    print('  \__ \/ __ \/ __ \/ __  / __ `/ __ \   ______    \__ \/ _ \/ __ `/ ___/ ___/ __ \\')
    print(' ___/ / / / / /_/ / /_/ / /_/ / / / /  /_____/   ___/ /  __/ /_/ / /  / /__/ / / /')
    print('/____/_/ /_/\____/\__,_/\__,_/_/ /_/            /____/\___/\__,_/_/   \___/_/ /_/ ')
    print(color.END)
    print(color.YELLOW + \
        '[!] Legal Disclaimer: We aren\'t responsible for bad use of this tool!')
    print(color.END)


def dateСonvert(string):
    date_object = datetime.strptime(string, '%Y-%m-%dT%H:%M:%S.%f')
    return date_object.strftime('%Y-%m-%d %H:%M:%S')


def ipRange(start_ip, end_ip):
    start = list(map(int, start_ip.split('.')))
    end = list(map(int, end_ip.split('.')))
    temp = start
    ip_range = []

    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_range.append('.'.join(map(str, temp)))

    return ip_range


def saveInfo(host, o):
    o.write('IP: %s\n' % host['ip_str'])
    o.write('Organization: %s\n' % host.get('org', 'n/a'))
    o.write('ASN: %s\n' % host['asn'])
    o.write('Country: %s\n' % host['country_name'])
    o.write('Operating System: %s\n' % host.get('os', 'n/a'))
    o.write('Hostnames:\n')
    if len(host['hostnames']) == 0:
        o.write('  [-] No hostnames\n')
    else:
        for i in host['hostnames']:
            o.write('  [+] %s\n' % str(i))
    o.write('Ports:\n')
    for item in host['data']:
        o.write('  [+] %s\n' % item['port'])
    o.write('Last update: %s\n' % dateСonvert(host['last_update']))


def printInfo(host):
    print(color.TITLE + 'IP: ' + color.END + '%s' % host['ip_str'])
    print(color.TITLE + \
        'Organization: ' + color.END + '%s' % host.get('org', 'n/a'))
    print(color.TITLE + 'ASN: ' + color.END + '%s' % host['asn'])
    print(color.TITLE + 'Country: ' + color.END + '%s' % host['country_name'])
    print(color.TITLE + \
        'Operating System: ' + color.END + '%s' % host.get('os', 'n/a'))
    print(color.TITLE + 'Hostnames:' + color.END)
    if len(host['hostnames']) == 0:
        print(color.FAIL + '  [-] ' + color.END + 'No hostnames')
    else:
        for i in host['hostnames']:
            print(color.GREEN + '  [+] ' + color.END + i)
    print(color.TITLE + 'Ports: ' + color.END)
    for item in host['data']:
        print(color.GREEN + '  [+] ' + color.END + '%s' % item['port'])
    print(color.TITLE + 'Last update: ' + color.END + '%s' 
        % dateСonvert(host['last_update']))


if __name__ == '__main__':
    banner()
    parser = optparse.OptionParser()
    parser.add_option('-i', '--ip', dest='ip', help='info about one host', default='')
    parser.add_option('-l', '--list', dest='list', help='info about a list of hosts', default='')
    parser.add_option('--setkey', dest='setkey', help='set your api key automatically', default='')
    parser.add_option('-r', '--range', dest='range', help='scan a range of ips. ex: 192.168.1.1-192.168.1.255', default='')
    parser.add_option('-o', '--output', dest='output', help='specify a output file', default='')
    parser.set_defaults(scantype='-sT')
    options, args = parser.parse_args()

    if options.setkey != '':
        SHODAN_API_KEY = options.setkey

    if SHODAN_API_KEY == '':
        print('You need to set the API Key in the file ' + \
            '\'shodan-search.py\' or with the \'--setkey\' option.')
        sys.exit()

    api = shodan.Shodan(SHODAN_API_KEY)
        
    if options.ip != '' and options.list != '':
        print('You can\'t use \'-i\' option with \'-l\'!')
        sys.exit()

    if options.output != '':
        if os.path.isfile(options.output):
            try:
                ans = str(input(color.FAIL + '[-] ' + \
                    color.END + 'File already exists, if you continue it will ' + \
                    'erase all the content of the file. continue? (y/N): '))
                if ans != 'y' and ans != 'Y':
                    print(color.GREEN + '[+] ' + color.END + 'Exiting...')
                    sys.exit()
            except SyntaxError:
                print(color.GREEN + '[+] ' + color.END + 'Exiting...')
                sys.exit()
        o = open(options.output, 'w')

    if options.ip != '':
        if options.output != '':
            try:
                print(color.GREEN + '[+] ' + color.END + \
                    'Writing information about hosts to the file')
                host = api.host(options.ip)
                saveInfo(host, o)
            except Exception as e:
                o.write('IP: %s\n' % options.ip)
                o.write('[-] ' + str(e) + '\n\n')
        else:
            try:
                host = api.host(options.ip)
                printInfo(host)
            except Exception as e:
                print(color.TITLE + 'IP: ' + color.END + '%s' % options.ip)
                print(color.FAIL + '[-] ' + color.END + str(e))
                print()
    elif options.list != '':
        f = open(options.list)
        if options.output != '':
            print(color.GREEN + '[+] ' + color.END + \
                'Writing information about hosts to the file')
            for ip in f.readlines():
                try:
                    host = api.host(ip)
                    saveInfo(host, o)
                    o.write('\n')
                except Exception as e:
                    o.write('IP: %s\n' % str(ip))
                    o.write('[-] ' + str(e) + '\n\n')
        else:
            for ip in f.readlines():
                try:
                    host = api.host(ip)
                    printInfo(host)
                    print()
                except Exception as e:
                    print(color.TITLE + 'IP: ' + color.END + '%s' % ip)
                    print(color.FAIL + '[-] ' + color.END + str(e))
                    print()
    elif options.range != '':
        first = options.range.split('-')[0]
        second = options.range.split('-')[1]

        # Verify if is a valid range
        if len(first.split('.')) != 4 or len(second.split('.')) != 4:
            print(color.FAIL + '[-]' + color.END + \
                ' Invalid range! see the help to use the --range option.\n')
            sys.exit()

        # Verify if is a valid IP
        for i in first.split('.'):
            if int(i) > 255:
                print(color.FAIL + '[-]' + color.END + \
                    ' Invalid IP! see the help to use the --range option.\n')
                sys.exit()

        for i in second.split('.'):
            if int(i) > 255:
                print(color.FAIL + '[-]' + color.END + \
                    ' Invalid IP! see the help to use the --range option.\n')
                sys.exit()

        firstSplited = first.split('.')
        secondSplited = second.split('.')
        firstSum = int(firstSplited[0]) + int(firstSplited[1]) + \
            int(firstSplited[2]) + int(firstSplited[3])
        secondSum = int(secondSplited[0]) + int(secondSplited[1]) + \
            int(secondSplited[2]) + int(secondSplited[3])

        if(firstSum >= secondSum):
            print(color.FAIL + '[-]' + color.END + \
                ' Invalid range! see the help to use the --range option.\n')
            sys.exit()

        iprange = ipRange(first, second)

        if options.output != '':
            print(color.GREEN + '[+] ' + color.END + \
                'Writing information about hosts to the file')
            for ip in iprange:
                try:
                    host = api.host(ip)
                    saveInfo(host, o)
                    o.write('\n')
                except Exception as e:
                    o.write('IP: %s\n' % str(ip))
                    o.write('[-] ' + str(e) + '\n\n')
        else:
            for ip in iprange:
                try:
                    host = api.host(ip)
                    printInfo(host)
                    print()
                except Exception as e:
                    print(color.TITLE + 'IP: ' + color.END + '%s' % ip)
                    print(color.FAIL + '[-] ' + color.END + str(e))
                    print()
