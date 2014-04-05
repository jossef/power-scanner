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
    parser = argparse.ArgumentParser(description='Powmap - Cyber security cource TASK 2 Building Scanning tool')

    parser.add_argument('-iface_ip', dest='interface_ip_address', metavar='IP', help='network ip', required=True)
    parser.add_argument('-timeout', dest='timeout', metavar='TIME', type=int, help='timeout on socket connections (milliseconds)', required=True)

    args = parser.parse_args()

    ip_address_regex = re.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

    interface_ip_address = args.interface_ip_address
    if not ip_address_regex.match(interface_ip_address):
        print 'Invalid interface ip address: {0}'.format(interface_ip_address)
        parser.print_help()
        sys.exit(1)

    timeout = args.timeout

    return interface_ip_address, timeout


def main():
    # Verify user root
    if not os.geteuid() == 0:
        print "root required! please use 'sudo' to run as root"
        return 1

    # Verify not windows
    if sys.platform == 'win32':
        print "not supported on windows. linux only"
        return 1

    interface_ip_address, timeout = parse_command_line_args()

    # Create the mapper

    icmp_mapper = IcmpNetworkMapper(timeout=timeout)
    endpoints = icmp_mapper.map(interface_ip_address=interface_ip_address)

    # ------- === ------
    # Printing in a table


    print 'mapping ... (please be patient)'
    print

    for endpoint in endpoints:
        print endpoint

if __name__ == "__main__":
    main()
