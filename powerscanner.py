import argparse
import re
import struct
import uuid
import sys
from struct import *
import sys
import os
import array
import fcntl

import socket
import fcntl
import struct
import array

from ping import *
from multiprocessing.pool import ThreadPool
from powscan_common.banner_grabber import BannerGrabber

from powscan_common.banner_helper import *
from powscan_common.port_helper import get_port_info
from powscan_common.port_scanner import FullTcpScanner
from powscan_common.networking_helper import *
from prettytable import PrettyTable

__author__ = 'jossef'


def parse_command_line_args():
    parser = argparse.ArgumentParser(description='Pyscan - TASK 2 - Building Scanning tool')

    parser.add_argument('-ip', dest='ip_address', metavar='IP', help='target ip address (v4 only)', required=True)
    parser.add_argument('-t', dest='time_interval', metavar='TIME', type=int,
                        help='time interval between each scan (milliseconds)', required=True)
    parser.add_argument('-pt', dest='protocol_type', metavar='PROTOCOL', choices=['UDP', 'TCP', 'ICMP'],
                        help='protocol type [UDP/TCP/ICMP]', required=True)
    parser.add_argument('-p', dest='ports', metavar='PORT', nargs='+',
                        help='ports can be range : -p 22-54 \ncan be single port : -p 80 \ncan be combination (space separated) : -p 80 43 23 125]',
                        required=True)
    parser.add_argument('-type', dest='scan_type', metavar='TYPE', choices=['full', 'stealth', 'fin', 'ack'],
                        help='scan type [full,stealth,fin,ack]', required=True)
    parser.add_argument('-b', dest='grab_banner', action='store_true',
                        help='bannerGrabber status (Should work only for TCP)')

    args = parser.parse_args()

    port_regex = re.compile(
        "^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])-([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$|^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$")

    ip_address_regex = re.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

    grab_banner = args.grab_banner
    ip_address = args.ip_address
    if not ip_address_regex.match(ip_address):
        print 'Invalid ip address: {0}'.format(ip_address)
        parser.print_help()
        return 1

    time_interval = args.time_interval
    protocol_type = args.protocol_type
    scan_type = args.scan_type
    ports = []

    try:
        # --== ==-- --== ==--
        # Parse the port ranges
        for item in args.ports:
            if not port_regex.match(item):
                raise Exception('Port should be number or number range i.e. "x" or "x-y". got {0}'.format(item))

            # Port range i.e. a-b
            if '-' in item:

                split = item.split('-')
                item1 = int(split[0])
                item2 = int(split[1])

                if item1 == item2:
                    ports.append(int(item1))
                elif item1 < item2:
                    for port in range(item1, item2 + 1):
                        ports.append(int(port))
                else:
                    for port in range(item2, item1 + 1):
                        ports.append(int(port))

            # Single port
            else:
                ports.append(int(item))

        # Remove duplicates
        ports = list(set(ports))

        print ports

    except Exception as ex:
        print 'Arguments parse error: {0}'.format(ex)
        parser.print_help()
        return 1

        # --== ==-- --== ==--



def pool_worker(address, port):
    grabber = BannerGrabber.create(address, port)
    return grabber.get_banner()


banner_grabbing_thread_pool = ThreadPool(processes=10)
banner_grabbing_async_results = []


def print_banners_test():
    ftps = ['ftp.freshrpms.net', 'ftp.heanet.ie', 'ftp.rediris.es', 'ftp.tu-chemnitz.de', 'ftp.es.kde.org',
            'ftp.esat.net', 'ftp.leo.org', 'ftp.mirror.nl', 'ftp.it.freebsd.org', 'ftp.gwdg.de', 'ftp.lublin.pl',
            'ftp.rhnet. is', 'ftp.de.netbsd.org', 'ftp.iij.ad.jp', 'ftp.bv.kernel.org', 'ftp.ussg.iu.edu',
            'ftp.aist-nara.ac.jp', 'ftp.uni-bayreuth.de', 'ftp.ch.freebsd.org', 'ftp.servage.com',
            'ftp.swfwmd.state.fl.us', 'ftp.mozilla.org']
    #ftps =[]

    for ftp in ftps:
        async_result = banner_grabbing_thread_pool.apply_async(pool_worker, (ftp, 21))
        banner_grabbing_async_results.append(async_result)

    smtps = ['smtp.gmail.com', 'smtp.live.com', 'smtp.mail.yahoo.com', 'smtp.mail.yahoo.co.uk', 'smtp.o2.ie',
             'smtp.att.yahoo.com', 'smtp.ntlworld.com', 'smtp.orange.net', 'smtp.wanadoo.co.uk', 'smtp.live.com',
             'smtp.1and1.com', 'outgoing.verizon.net', 'smtp.comcast.net', 'smtp.mail.com']

    for smtp in smtps:
        async_result = banner_grabbing_thread_pool.apply_async(pool_worker, (smtp, 25))
        banner_grabbing_async_results.append(async_result)

    https = ['www.jossef.com', 'www.gmail.com', 'www.ynet.co.il', 'www.colman.ac.il']
    #https =[]
    for http in https:
        async_result = banner_grabbing_thread_pool.apply_async(pool_worker, (http, 80))
        banner_grabbing_async_results.append(async_result)


    # ------- === ------
    # Printing like a boss

    x = PrettyTable(["Server", "Operating System", "Port"])
    x.align["Server"] = "l"
    x.align["Operating System"] = "l"
    x.align["Port"] = "l"

    for banner_grabbing_async_result in banner_grabbing_async_results:
        server, operating_system, port = banner_grabbing_async_result.get()
        if not server and not operating_system:
            continue

        x.add_row([server, operating_system, get_port_info(port)])

    print x


def powa():
    scanner = FullTcpScanner('10.0.2.2', sleep_in_milliseconds=0)
    scan_results = scanner.scan()

    for item in scan_results:
        print item


def enumerate_interfaces_test():
    interfaces = get_interfaces()

    for item in interfaces:

        name = item[0]
        ip = item[1]
        mac = item[3]

        if 'lo' in name:
            continue

        network_addresses = get_network_addresses(ip, mac)
        for network_address in network_addresses:
            print network_address

        print item

        print '-----------------------'
        print


def main():
    #print_banners_test()
    #powa()
    enumerate_interfaces_test()

    return


if __name__ == "__main__":
    main()
