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
from powscan_common.socket_helper import *

__author__ = 'jossef'

#
# def smtp_banner_grabber(address, port = 25):
#     sock = None
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         socket_connect(sock, address, port)
#         banner = socket_recieve(sock)
#
#         operating_system = None
#         server = None
#
#         # Lets scrape for any hints
#         banner_lines = banner.split('\n')
#         banner_lines = [item.strip() for item in banner_lines]
#
#         for banner_line in banner_lines:
#             server, operating_system = get_smtp_banner_info(banner_line)
#             if server or operating_system:
#                 break
#
#         return server, operating_system, port
#
#
#     except Exception as ex:
#         return None, None, port
#
#     finally:
#         if sock:
#             sock.close()
#
# def ftp_banner_grabber(address, port = 21):
#     sock = None
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         socket_connect(sock, address, port)
#         banner = socket_recieve(sock)
#
#         operating_system = None
#         server = None
#
#         # Lets scrape for any hints
#         banner_lines = banner.split('\n')
#         banner_lines = [item.strip() for item in banner_lines]
#
#         for banner_line in banner_lines:
#             server, operating_system = get_ftp_banner_info(banner_line)
#             if server or operating_system:
#                 break
#
#         return server, operating_system, port
#
#
#     except Exception as ex:
#         return None, None, port
#
#     finally:
#         if sock:
#             sock.close()
#
#
# def http_banner_grabber(address, port = 80):
#     sock = None
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         socket_connect(sock, address, port)
#
#         sock.send("HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % address)
#         banner = socket_recieve(sock)
#
#         operating_system = None
#         server = None
#
#         # Lets Search for the 'Server: ' instance
#         banner_lines = banner.split('\n')
#         banner_lines = [item.strip() for item in banner_lines]
#
#         server_prefix = 'server:'
#         server_line = (item for item in banner_lines if item.lower().startswith(server_prefix)).next()
#         if server_line:
#             server_line = server_line[len(server_prefix):].strip()
#
#             server, operating_system = get_http_banner_info(server_line)
#
#         return server, operating_system, port
#
#     except Exception as ex:
#         return None, None, port
#
#     finally:
#         if sock:
#             sock.close()



def pool_worker(address, port ):
    grabber = BannerGrabber.create(address, port)
    return grabber.get_banner()

banner_grabbing_thread_pool = ThreadPool(processes=10)
banner_grabbing_async_results = []


def main():
    ftps = ['ftp.freshrpms.net',
            'ftp.heanet.ie',
            'ftp.rediris.es',
            'ftp.tu-chemnitz.de',
            'ftp.es.kde.org',
            'ftp.esat.net',
            'ftp.leo.org',
            'ftp.mirror.nl',
            'ftp.it.freebsd.org',
            'ftp.gwdg.de',
            'ftp.lublin.pl',
            'ftp.rhnet. is',
            'ftp.de.netbsd.org',
            'ftp.iij.ad.jp',
            'ftp.bv.kernel.org',
            'ftp.ussg.iu.edu',
            'ftp.aist-nara.ac.jp',
            'ftp.uni-bayreuth.de',
            'ftp.ch.freebsd.org',
            'ftp.servage.com',
            'ftp.swfwmd.state.fl.us',
            'ftp.mozilla.org']

    #ftps =[]
    for ftp in ftps:
        async_result = banner_grabbing_thread_pool.apply_async(pool_worker, (ftp, 21))
        banner_grabbing_async_results.append(async_result)

    smtps = ['smtp.gmail.com', 'smtp.live.com', 'smtp.mail.yahoo.com', 'smtp.mail.yahoo.co.uk', 'smtp.o2.ie', 'smtp.att.yahoo.com', 'smtp.ntlworld.com', 'smtp.orange.net', 'smtp.wanadoo.co.uk', 'smtp.live.com', 'smtp.1and1.com', 'outgoing.verizon.net', 'smtp.comcast.net', 'smtp.mail.com']

    for smtp in smtps:
        async_result = banner_grabbing_thread_pool.apply_async(pool_worker, (smtp, 25))
        banner_grabbing_async_results.append(async_result)

    https = ['www.jossef.com', 'www.gmail.com', 'www.ynet.co.il', 'www.colman.ac.il']
    #https =[]
    for http in https:
        async_result = banner_grabbing_thread_pool.apply_async(pool_worker, (http, 80))
        banner_grabbing_async_results.append(async_result)

    for banner_grabbing_async_result in banner_grabbing_async_results:

        result = banner_grabbing_async_result.get()
        if not result:
            continue

        print result
        print '.................................... \r\n \r\n '

    print 'thats it'

    return
    p = CmdlinePinger('8.8.8.8', 1)
    p.ping()
    summary = p.get_summary()

    print summary

    return
    interfaces = all_interfaces()

    for interface in interfaces:
        ar = ArpRequest('212.179.154.222', interface['name'], interface['ip'])
        print ar.request()

    return 0

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


if __name__ == "__main__":
    main()
