import os
import struct
import array
import struct
from socket import htons, ntohs

__author__ = 'Jossef Harush'
import abc


class Packet(object):
    __metaclass__ = abc.ABCMeta

    def _validate_checksum(self, raw_packet_bytes):
        """
            Validates the given raw_packet_bytes
            raises ValueError if invalid checksum
        """
        result = cksum(raw_packet_bytes)

        # result should be 0 if valid
        if result != 0:
            raise ValueError('Checksum mismatch')


    def serialize(self):
        """
            Serializes the current packet instance into a raw packet bytes
            returns packet bytes
        """
        return self._serialize()


    @abc.abstractmethod
    def _serialize(self):
        """
            Abstract method -
            Serializes the current packet instance into a raw packet bytes
            returns packet bytes
        """
        pass


    def deserialize(self, raw_packet_bytes):
        """
            Deserializes the raw_packet_bytes into an instance of the inheritor
        """
        self._validate_checksum(raw_packet_bytes)
        self._deserialize(raw_packet_bytes)


    @abc.abstractmethod
    def _deserialize(self, raw_packet_bytes):
        """
            Abstract method -
            Deserializes the raw_packet_bytes into an instance of the inheritor
        """
        pass


# -- == -- =-- == -- =-- == -- =-- == -- =-- == -- =
# ICMP Zone


# -- == --
# Enum IcmpPacketType

class IcmpPacketType(object):
    ICMP_MINLEN = 8
    ICMP_MASKLEN = 12
    ICMP_ECHOREPLY = 0
    ICMP_UNREACH = 3
    ICMP_UNREACH_NET = 0
    ICMP_UNREACH_HOST = 1
    ICMP_UNREACH_PROTOCOL = 2
    ICMP_UNREACH_PORT = 3
    ICMP_UNREACH_NEEDFRAG = 4
    ICMP_UNREACH_SRCFAIL = 5
    ICMP_SOURCEQUENCH = 4
    ICMP_REDIRECT = 5
    ICMP_REDIRECT_NET = 0
    ICMP_REDIRECT_HOST = 1
    ICMP_REDIRECT_TOSNET = 2
    ICMP_REDIRECT_TOSHOST = 3
    ICMP_ECHO = 8
    ICMP_TIMXCEED = 11
    ICMP_TIMXCEED_INTRANS = 0
    ICMP_TIMXCEED_REASS = 1
    ICMP_PARAMPROB = 12
    ICMP_TSTAMP = 13
    ICMP_TSTAMPREPLY = 14
    ICMP_IREQ = 15
    ICMP_IREQREPLY = 16
    ICMP_MASKREQ = 17
    ICMP_MASKREPLY = 18


# -- == --
# IcmpPacket

# ICMP Header Format http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
# |type(8)|code(8)|checksum(16)|id(4)|sequence(4)|dynamic structure aka data(32)|

class IcmpPacket(Packet):
    def __init__(self, type=IcmpPacketType.ICMP_ECHO, code=0, id=None, sequence=0, data='Power Scanner ICMP'):
        """
        data - whatever you want to add to the icmp packet
        id - max 32
        sequence - max 32
        """

        self.type = type
        self.code = code

        # id not initialized
        if not id:
            # Treat the hosting process's pid as id
            self.id = os.getpid()
        else:
            self.id = id

        self.sequence = sequence
        self.data = data

    def _serialize(self):
        # icmp request :
        #   |type(8)|code(8)|checksum(16)|id(4)|sequence(4)|dynamic structure aka data(variable)|

        # Q - 8 bytes
        # L - 4 bytes
        # H - 2 bytes
        # B - 1 byte

        type = struct.pack('B', self.type)
        code = struct.pack('B', self.code)
        checksum_result = struct.pack('H', 0)
        id = struct.pack('H', self.id)
        sequence = struct.pack('H', self.sequence)

        packet_without_checksum = type + code + checksum_result + id + sequence + self.data
        checksum_result = cksum(packet_without_checksum)
        checksum_result = struct.pack('H', checksum_result)
        packet = type + code + checksum_result + id + sequence + self.data

        return packet

    def _deserialize(self, raw_packet_bytes):
        self.type = ord(raw_packet_bytes[0])
        self.code = ord(raw_packet_bytes[1])
        elts = struct.unpack('HHH', raw_packet_bytes[2:8])
        cksum = 0
        [cksum, self.id, self.sequence] = map(lambda x: x & 0xffff, elts)
        self.data = raw_packet_bytes[8:]


# -- == -- =-- == -- =-- == -- =-- == -- =-- == -- =
# Helper methods taken from an open source 'pinger'
# written by Jeremy Hylton, jeremy@cnri.reston.va.us


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff


def cksum(s):
    if len(s) & 1:
        s = s + '\0'
    words = array.array('h', s)
    sum = 0
    for word in words:
        sum = sum + (word & 0xffff)
    hi = sum >> 16
    lo = sum & 0xffff
    sum = hi + lo
    sum = sum + (sum >> 16)
    return (~sum) & 0xffff


# Should generalize from the *h2net patterns

# This python code is suboptimal because it is based on C code where
# it doesn't cost much to take a raw buffer and treat a section of it
# as a u_short.

def gets(s):
    return struct.unpack('h', s)[0] & 0xffff


def mks(h):
    return struct.pack('H', h)


def iph2net(s):
    len = htons(gets(s[2:4]))
    id = htons(gets(s[4:6]))
    off = htons(gets(s[6:8]))
    return s[:2] + mks(len) + mks(id) + mks(off) + s[8:]


def net2iph(s):
    len = ntohs(gets(s[2:4]))
    id = ntohs(gets(s[4:6]))
    off = ntohs(gets(s[6:8]))
    return s[:2] + mks(len) + mks(id) + mks(off) + s[8:]


def udph2net(s):
    sp = htons(gets(s[0:2]))
    dp = htons(gets(s[2:4]))
    len = htons(gets(s[4:6]))
    return mks(sp) + mks(dp) + mks(len) + s[6:]


def net2updh(s):
    sp = ntohs(gets(s[0:2]))
    dp = ntohs(gets(s[2:4]))
    len = ntohs(gets(s[4:6]))
    return mks(sp) + mks(dp) + mks(len) + s[6:]

