import argparse
import logging
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

from multiprocessing.pool import ThreadPool
from powscan_common.banner_grabber import *
from powscan_common.network_mapper import *
from powscan_common.port_helper import *
from powscan_common.port_scanner import *
from powscan_common.networking_helper import *
from prettytable import PrettyTable

__author__ = 'Jossef Harush'


def parse_command_line_args():
    parser = argparse.ArgumentParser(description='Powscan - Cyber security cource TASK 2 Building Scanning tool')

    parser.add_argument('-iface_ip', dest='interface_ip_address', metavar='IP', help='sending interface ip address (v4 only)', required=True)
    parser.add_argument('-target_ip', dest='target_ip_address', metavar='IP', help='target ip address (v4 only)', required=True)
    parser.add_argument('-interval', dest='delay', metavar='TIME', type=int, help='time interval between each scan (milliseconds)', required=True)
    parser.add_argument('-timeout', dest='timeout', metavar='TIME', type=int, help='timeout on socket connections (milliseconds)', required=True)
    parser.add_argument('-ports', dest='ports', metavar='PORT', nargs='+', help='ports can be range : -p 22-54 \ncan be single port : -p 80 \ncan be combination (space separated) : -p 80 43 23 125]', required=True)
    parser.add_argument('-scan_type', dest='scan_type', metavar='TYPE', choices=['full_tcp', 'stealth', 'fin', 'ack', 'udp'], help='scan type [full,stealth,fin,ack]', required=True)
    parser.add_argument('-banner', dest='grab_banner', action='store_true', help='bannerGrabber status (Should work only for TCP)')

    args = parser.parse_args()

    port_regex = re.compile(
        "^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])-([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$|^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$")

    ip_address_regex = re.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

    grab_banner = args.grab_banner
    target_ip_address = args.target_ip_address
    if not ip_address_regex.match(target_ip_address):
        print 'Invalid ip address: {0}'.format(target_ip_address)
        parser.print_help()
        sys.exit(1)

    interface_ip_address = args.interface_ip_address
    if not ip_address_regex.match(interface_ip_address):
        print 'Invalid interface ip address: {0}'.format(interface_ip_address)
        parser.print_help()
        sys.exit(1)

    delay = args.delay
    timeout = args.timeout
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

    except Exception as ex:
        print 'port parse error: {0}\nthe correct format is PORT PORT PORT1-PORT2 ... '.format(ex)
        parser.print_help()
        sys.exit(1)

    return grab_banner, delay, timeout, target_ip_address, interface_ip_address, scan_type, ports


def main():
    # Verify user root
    if not os.geteuid() == 0:
        print "root required! please use 'sudo' to run as root"
        return 1

    # Verify not windows
    if sys.platform == 'win32':
        print "not supported on windows. linux only"
        return 1

    grab_banner, delay, timeout, target_ip_address, interface_ip_address, scan_type, ports = parse_command_line_args()

    # Create the scanner

    scanner = PortScanner.create(
        type=scan_type,
        source_ip=interface_ip_address,
        destination_ip=target_ip_address,
        ports=ports,
        sleep_in_milliseconds=delay,
        timeout_im_milliseconds=timeout)


    # ------- === ------
    # Printing in a table

    table_headers = None
    if grab_banner:
        table_headers = ["Target", "Port", "Port Description", "Scan Type", "Operating System", "Server"]
    else:
        table_headers = ["Target", "Port", "Port Description", "Scan Type"]

    x = PrettyTable(table_headers)

    print 'scanning ... (please be patient)'
    print

    opened_ports = scanner.scan()
    for opened_port in opened_ports:

        row = []

        if grab_banner:

            operating_system = None
            server = None
            try:
                banner_grabber = BannerGrabber.create(target_ip_address, opened_port)
                operating_system, server = banner_grabber.get_banner()
            except:
                pass

            if not operating_system:
                operating_system = ''

            if not server:
                server = ''

            row = [target_ip_address, str(opened_port), get_port_info(opened_port), scan_type, operating_system, server]
        else:
            row = [target_ip_address, str(opened_port), get_port_info(opened_port), scan_type]
        x.add_row(row)

    print x


if __name__ == "__main__":
    main()
