import argparse
import re
import socket
import uuid
import sys
from struct import *
import sys
import os
from arprequest import ArpRequest


__author__ = 'jossef'


# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8) + (ord(msg[i + 1]) )
        s = s + w

    s = (s >> 16) + (s & 0xffff);
    s = ~s & 0xffff
    return s


def send_arp(src_ip, dst_ip, sender_mac):
    #if_ipaddr = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((src_ip, socket.SOCK_RAW))

    sender_mac = sender_mac.replace(':', '').decode('hex')
    bcast_mac = pack('!6B', *(0xFF,) * 6)
    zero_mac = pack('!6B', *(0x00,) * 6)

    ARPOP_REQUEST = pack('!H', 0x0001)
    target_mac = zero_mac
    arpop = ARPOP_REQUEST
    sender_ip = pack('!4B', *[int(x) for x in src_ip.split('.')])
    target_ip = pack('!4B', *[int(x) for x in dst_ip.split('.')])

    arpframe = [
        ### ETHERNET
        # destination MAC addr
        bcast_mac,
        # source MAC addr
        sender_mac,
        # protocol type (=ARP)
        pack('!H', 0x0806),

        ### ARP
        # logical protocol type (Ethernet/IP)
        pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
        # operation type
        arpop,
        # sender MAC addr
        sender_mac,
        # sender IP addr
        sender_ip,
        # target hardware addr
        target_mac,
        # target IP addr
        target_ip
    ]

    # send the ARP
    sock.send(''.join(arpframe))

    return True


def get_most_suitable_interface(ip):
    interfaces = socket.gethostbyname_ex(socket.gethostname())
    # Send arp to all interfaces


def getHwAddr(ifname):
    #s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    #return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    pass


def scan_tcp_port(ip_address, port):
    #create a raw socket
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # tell kernel not to put in headers, since we are providing it
    my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


    # now start constructing the packet
    packet = '';

    # get the source ip from
    source_ip = '192.168.1.101'
    dest_ip = ip_address  # or socket.gethostbyname('www.google.com')

    # ip header fields
    ihl = 5
    version = 4
    tos = 0
    tot_len = 20 + 20  # python seems to correctly fill the total length, dont know how ??
    id = 54321  #Id of this packet
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 10  # python seems to correctly fill the checksum
    saddr = socket.inet_aton(source_ip)  #Spoof the source ip address if you want to
    daddr = socket.inet_aton(dest_ip)

    ihl_version = (version << 4) + ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

    # tcp header fields
    source = 1234  # source port
    dest = 80  # destination port
    seq = 0
    ack_seq = 0

    doff = 5  #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    offset_res = (doff << 4) + 0

    window = socket.htons(5840)  #   maximum allowed window size
    check = 0
    urg_ptr = 0

    # -- -- -- == -- -- --
    # Construct TCP flags

    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
    psh = psh + tcp_header;

    tcp_checksum = checksum(psh)

    # make the tcp header again and fill the correct checksum
    tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)

    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header

    #Send the packet finally - the port specified has no effect
    my_socket.sendto(packet, (dest_ip, 0 ))  # put this in a loop if you want to flood the target

    #put the above line in a loop like while 1: if you want to flood


def get_interfaces_info():
    """
    Due to lack of support in a good, cross platform solution for retrieval of network interfaces info (mac ip subnet),
    this helper function written.

        we could use netifaces (http://alastairs-place.net/projects/netifaces/) library
        the reason we did not used it is because it requires installation, which is not allowed by michael

    the function simply uses popen and launch ipconfig (on windows) or ifconfig (on linux) and parses the output
    """
    # Windows
    ip = None
    mac = None
    subnet = None

    if sys.platform == 'win32':

        for line in os.popen("ipconfig /all"):

            if ip and mac and subnet:
                yield {'ip': ip, 'mac': mac, 'subnet': subnet}
                ip = None
                mac = None
                subnet = None

            # Empty line - item separator
            if len(line.strip()) == 0:
                ip = None
                mac = None
                subnet = None
                continue

            if line.lstrip().startswith('IPv4 Address'):
                ip = line.split(':')[1].strip().replace('(Preferred)', '')

            if line.lstrip().startswith('Physical Address'):
                mac = line.split(':')[1].strip().replace('-', ':')

            if line.lstrip().startswith('Subnet Mask'):
                subnet = line.split(':')[1].strip()

    # Linux
    else:

        for line in os.popen("/sbin/ifconfig"):
            if ip and mac and subnet:
                yield {'ip': ip, 'mac': mac, 'subnet': subnet}
                ip = None
                mac = None
                subnet = None

            # Empty line - item separator
            if len(line.strip()) == 0:
                ip = None
                mac = None
                subnet = None
                continue

            ip_offset = line.lstrip().find('inet addr')
            if ip_offset > -1:
                ip = line[ip_offset:].strip().split(':')[1].strip().split(' ')[0]

            mac_offset = line.lstrip().find('HWaddr')
            if mac_offset > -1:
                mac = line[mac_offset:].strip().split(' ')[1].strip()

            mask_offset = line.lstrip().find('Mask')
            if mask_offset > -1:
                subnet = line[mask_offset:].strip().split(':')[1].strip()


def main():
    interfaces = get_interfaces_info()

    for interface in interfaces:
        ar = ArpRequest('8.8.8.8', interface['ip'])
        print ar.request()


    aprreq = ArpRequest()

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
