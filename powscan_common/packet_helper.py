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

class IcmpPacket(Packet):
    def __init__(self, type=IcmpPacketType.ICMP_ECHO, code=0, id=None, seq=0, data='12'):
        self.type = type
        self.code = code

        # id not initialized
        if not id:
            # Treat the hosting process's pid as id
            self.id = os.getpid()
        else:
            self.id = id

        self.seq = seq
        self.data = data

    def _serialize(self):
        idseq = struct.pack('hh', self.id, self.seq)
        packet_without_checksum = chr(self.type) + chr(self.code) + '\000\000' + idseq + self.data
        checksum = cksum(packet_without_checksum)
        packet = chr(self.type) + chr(self.code) + struct.pack('h', checksum) + idseq + self.data

        return packet

    def _deserialize(self, raw_packet_bytes):
        self.type = ord(raw_packet_bytes[0])
        self.code = ord(raw_packet_bytes[1])
        elts = struct.unpack('hhh', raw_packet_bytes[2:8])
        cksum = 0
        [cksum, self.id, self.seq] = map(lambda x: x & 0xffff, elts)
        self.data = raw_packet_bytes[8:]


# -- == -- =-- == -- =-- == -- =-- == -- =-- == -- =
# Helper methods taken from an open source 'pinger'
# written by Jeremy Hylton, jeremy@cnri.reston.va.us

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

