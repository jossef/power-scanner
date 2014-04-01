import select
import socket
import struct
import fcntl
import array


__author__ = 'Jossef Harush'


def socket_connect(socket, address, port, timeout=5):
    socket.settimeout(timeout)
    socket.connect((address, port))
    socket.settimeout(None)


def socket_recieve(socket, timeout=5, buffer_size=4096):
    socket.setblocking(0)

    ready = select.select([socket], [], [], timeout)

    if not ready[0]:
        raise Exception('timeout')

    data = socket.recv(buffer_size)
    return data


# Thanks to https://gist.github.com/pklaus/289646 for the snippet
# modification - added yield returns
def all_interfaces():
    max_possible = 128  # arbitrary. raise if needed.
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]

    namestr = names.tostring()

    for i in range(0, outbytes, 40):
        response = dict()
        response['name'] = namestr[i:i + 16].split('\0', 1)[0]
        response['hex_ip'] = namestr[i + 20:i + 24]
        response['ip'] = str(format_ip(namestr[i + 20:i + 24]))
        yield response


def format_ip(addr):
    return str(ord(addr[0])) + '.' + \
           str(ord(addr[1])) + '.' + \
           str(ord(addr[2])) + '.' + \
           str(ord(addr[3]))