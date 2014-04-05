import select
import socket
import struct
import fcntl
import array


__author__ = 'Jossef Harush'


def get_operating_system_by_ttl(ttl):
    pass


def socket_connect(sock, address, port, timeout=0.5):
    sock.settimeout(timeout)
    sock.connect((address, port))
    sock.settimeout(None)


def socket_receive(sock, timeout_in_seconds=0.5):
    sock.settimeout(timeout_in_seconds)
    response = sock.recvfrom(65535)[0][0:]
    return response


def socket_send_receive(sock, data, address, port, timeout_in_seconds=0.5):
    """
    packet - instance of Packet class defined in packet_helper

    * raises an exception if timed out
    """

    sock.settimeout(timeout_in_seconds)

    destination_info = (address, port)
    sock.sendto(data, destination_info)
    response, addr = sock.recvfrom(65535)
    return response, addr


def create_raw_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)


def create_icmp_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)


def create_tcp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock


def create_udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    return sock


def convert_v4_address_bits_to_string(ip_address_bits):
    """
    return v4 address bits to string

    for example: '11111111111111110000000000000000' -> '255.255.0.0'
    """

    ip_address_octets = [int(ip_address_bits[i:i + 8], 2) for i in range(0, len(ip_address_bits), 8)]
    ip_address = '.'.join([str(octet) for octet in ip_address_octets])

    return ip_address


def convert_v4_address_string_to_bits(ip_address):
    """
    return v4 address string to bits

    for example: '255.255.0.0' -> '11111111111111110000000000000000'
    """
    return ''.join([bin(int(octet))[2:].zfill(8) for octet in ip_address.split('.')])


def convert_v4_address_string_to_hex(ip_address):
    """
    return v4 address string to bits

    for example: '255.255.0.0' -> \ff\ff\00\00 (big endian)
    """

    ip_address_bits = convert_v4_address_string_to_bits(ip_address)
    ip_address_hex = struct.pack('!I', int(ip_address_bits, 2))

    return ip_address_hex


def convert_v4_address_hex_to_string(ip_address_hex):
    """
    return v4 address hex to string

    for example: '\ff\ff\ff\00' -> 255.255.255.0
    """

    ip_address_bits = bin(ip_address_hex)[2:].zfill(32)
    ip_address = convert_v4_address_bits_to_string(ip_address_bits)

    return ip_address


def get_network_endpoint_addresses(ip_address, subnet_mask):
    """
    returns a list of available ip addresses for endpoints
    """

    # Let's say the mask is:
    # ..1111000.00000

    # n = 0's count
    # total endpoints = 2^n -1 (-1 for the non zero address for endpoint)

    network_address = get_network_address(ip_address, subnet_mask)
    network_address_bits = convert_v4_address_string_to_bits(network_address)

    subnet_mask_bits = convert_v4_address_string_to_bits(subnet_mask)
    zeros_in_subnet = subnet_mask_bits.count('0')

    # -2 for
    #   1. not including the 0 as endpoint address (illegal as endpoint address)
    #   2. not including the last address (this is the subnet broadcast address)
    total_endpoins = pow(2, zeros_in_subnet) - 2


    # Let's enumerate for the endpoint from 1 to total_endpoins
    # on each iteration, bitwise OR each item with the network_address_bits
    # this will give us the desired ip address
    for endpoint in range(1, total_endpoins + 1):
        # The magical OR :)
        # converts the network_address into a big number, OR this number with the current endpoint
        endpoint_address_bits = bin(int(network_address_bits, 2) | endpoint)[2:].zfill(32)
        endpoint_address = convert_v4_address_bits_to_string(endpoint_address_bits)

        yield endpoint_address


def get_network_address(ip_address, subnet_mask):
    """
    Simply masks the ip address with the subnet to get the network address
    returns the network address

    """
    # Convert ip_address to list of 4 integers
    ip_address_octets = [int(octet) for octet in ip_address.split('.')]
    subnet_mask_octets = [int(octet) for octet in subnet_mask.split('.')]

    network_address_octets = [(ip_address_octets[i] & subnet_mask_octets[i]) for i in range(4)]

    network_address = '.'.join([str(octet) for octet in network_address_octets])

    return network_address


# -- == -- == -- == -- == -- == -- == -- == -- == -- == -- ==
# Thanks to http://stackoverflow.com/questions/159137/getting-mac-address for the snippet
def get_mac_address(interface_name):
    """
    Get the mac address for the given interface_name

        return string format xx:xx:xx:xx:xx
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface_name[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]


# -- == -- == -- == -- == -- == -- == -- == -- == -- == -- ==
# Thanks to http://stackoverflow.com/questions/936444/retrieving-network-mask-in-python for the snippet
def get_subnet_mask(interface_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s', interface_name))[20:24])


# -- == -- == -- == -- == -- == -- == -- == -- == -- == -- ==
# Thanks to https://gist.github.com/pklaus/289646 for the snippet
# modification - added yield returns
def ip_address_bytes_to_string(ip_address_bytes):
    """
    formats the ip into a 4-octet human friendly format
    xxx.xxx.xxx.xxx
    """
    return str(ord(ip_address_bytes[0])) + '.' + \
           str(ord(ip_address_bytes[1])) + '.' + \
           str(ord(ip_address_bytes[2])) + '.' + \
           str(ord(ip_address_bytes[3]))


def get_interfaces():
    """
    Enumerate interfaces (name, ip, mac, subnet).

        yield return a 3-tuple:
        interface_name, interface_ip_address, interface_mac_address, interface_subnet_mask
    """
    max_possible = 128  # arbitrary. raise if needed.
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(s.fileno(), 0x8912, struct.pack('iL', bytes, names.buffer_info()[0])))[0]

    namestr = names.tostring()

    for i in range(0, outbytes, 40):
        interface_name = namestr[i:i + 16].split('\0', 1)[0]
        interface_ip_address = str(ip_address_bytes_to_string(namestr[i + 20:i + 24]))
        interface_mac_address = get_mac_address(interface_name)
        interface_subnet_mask = get_subnet_mask(interface_name)

        yield interface_name, interface_ip_address, interface_mac_address, interface_subnet_mask
