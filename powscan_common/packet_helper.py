import time

__author__ = 'Jossef Harush'

import os
import struct
import array
import struct
from socket import htons, ntohs
from powscan_common.networking_helper import *
import abc


class Packet(object):
    __metaclass__ = abc.ABCMeta

    def _checksum(self, msg):
        s = 0

        if len(msg) % 2 != 0:
            msg += chr(0)

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8 )
            s = s + w

        s = (s >> 16) + (s & 0xffff);
        s = s + (s >> 16);

        #complement and mask to 4 byte short
        s = ~s & 0xffff

        return s

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
        self._deserialize(raw_packet_bytes)


    @abc.abstractmethod
    def _deserialize(self, raw_packet_bytes):
        """
            Abstract method -
            Deserializes the raw_packet_bytes into an instance of the inheritor
        """
        pass


# --==-- ==--== ==---== --==-- ==--== ==---== --==-- ==--== ==---== --==-- ==--== ==---==
# Internet Control Message Protocol (ICMP) :


# -- == --
# Enum IcmpPacketType

class IcmpType(object):
    minlen = 8
    masklen = 12
    echoreply = 0
    unreach = 3
    unreach_net = 0
    unreach_host = 1
    unreach_protocol = 2
    unreach_port = 3
    unreach_needfrag = 4
    unreach_srcfail = 5
    sourcequench = 4
    redirect = 5
    redirect_net = 0
    redirect_host = 1
    redirect_tosnet = 2
    redirect_toshost = 3
    echo = 8
    timxceed = 11
    timxceed_intrans = 0
    timxceed_reass = 1
    paramprob = 12
    tstamp = 13
    tstampreply = 14
    ireq = 15
    ireqreply = 16
    maskreq = 17
    maskreply = 18


# -- == --
# IcmpPacket

# ICMP Header Format http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
# |type(8)|code(8)|checksum(16)|id(4)|sequence(4)|dynamic structure aka data(32)|

class IcmpPacket(Packet):
    def __init__(self,
                 type=IcmpType.echo,
                 code=0,
                 id=None,
                 sequence=0,
                 checksum=0,
                 payload='Power Scanner ICMP'):

        self.type = type
        self.code = code

        # id not initialized
        if not id:
            # Treat the hosting process's pid as id
            self.id = os.getpid() & 0xFFFF
        else:
            self.id = id

        self.sequence = sequence
        self.checksum = checksum
        self.payload = payload

    def _serialize(self):
        # icmp request :
        #   |type(8)|code(8)|checksum(16)|id(4)|sequence(4)|dynamic structure aka data(variable)|

        # Q - 8 bytes
        # L - 4 bytes
        # H - 2 bytes
        # B - 1 byte

        type = struct.pack('!B', self.type)
        code = struct.pack('!B', self.code)
        checksum_result = struct.pack('H', 0)
        id = struct.pack('!H', self.id)
        sequence = struct.pack('!H', self.sequence)

        packet_without_checksum = type + \
                                  code + \
                                  checksum_result + \
                                  id + \
                                  sequence + \
                                  self.payload

        checksum_result = self._checksum(packet_without_checksum)
        checksum_result = struct.pack('H', checksum_result)

        packet = type + \
                 code + \
                 checksum_result + \
                 id + \
                 sequence + \
                 self.payload

        return packet

    def _deserialize(self, raw_packet_bytes):
        self.type = struct.unpack('!B', raw_packet_bytes[0:1])[0]
        self.code = struct.unpack('!B', raw_packet_bytes[1:2])[0]
        self.checksum = struct.unpack('H', raw_packet_bytes[2:4])[0]
        self.id = struct.unpack('!H', raw_packet_bytes[4:6])[0]
        self.sequence = struct.unpack('!H', raw_packet_bytes[6:8])[0]
        self.payload = raw_packet_bytes[8:]


# --==-- ==--== ==---== --==-- ==--== ==---== --==-- ==--== ==---== --==-- ==--== ==---==
# Internet Protocol (IP) :

class IpServiceType(object):
    lowdelay = 0x10
    throughput = 0x08
    reliability = 0x04
    netcontrol = 0xe0
    internetcontrol = 0xc0
    critic_ecp = 0xa0
    flashoverride = 0x80
    flash = 0x60
    immediate = 0x40
    priority = 0x20
    routine = 0x00


class IpFlags(object):
    dont_fragment = int('010', 2)
    more_fragment = int('001', 2)
    fragment_if_necessary = int('000', 2)


class IpProtocol(object):
    hopopt = 0  # ipv6 hop_by_hop option
    icmp = 1  # internet control message protocol
    igmp = 2  # internet group management protocol
    ggp = 3  # gateway_to_gateway protocol
    ip_in_ip = 4  # ip_within_ip (encapsulation)
    st = 5  # internet stream protocol
    tcp = 6  # transmission control protocol
    cbt = 7  # core_based trees
    egp = 8  # exterior gateway protocol
    igp = 9  # interior gateway protocol (any private interior gateway (used by cisco for their igrp))
    bbn_rcc_mon = 10  # bbn rcc monitoring
    nvp_ii = 11  # network voice protocol
    pup = 12  # xerox pup
    argus = 13  # argus
    emcon = 14  # emcon
    xnet = 15  # cross net debugger
    chaos = 16  # chaos
    udp = 17  # user datagram protocol
    mux = 18  # multiplexing
    dcn_meas = 19  # dcn measurement subsystems
    hmp = 20  # host monitoring protocol
    prm = 21  # packet radio measurement
    xns_idp = 22  # xerox ns idp
    trunk_1 = 23  # trunk_1
    trunk_2 = 24  # trunk_2
    leaf_1 = 25  # leaf_1
    leaf_2 = 26  # leaf_2
    rdp = 27  # reliable datagram protocol
    irtp = 28  # internet reliable transaction protocol
    iso_tp4 = 29  # iso transport protocol class 4
    netblt = 30  # bulk data transfer protocol
    mfe_nsp = 31  # mfe network services protocol
    merit_inp = 32  # merit internodal protocol
    dccp = 33  # datagram congestion control protocol
    _3pc = 34  # third party connect protocol
    idpr = 35  # inter_domain policy routing protocol
    xtp = 36  # xpress transport protocol
    ddp = 37  # datagram delivery protocol
    idpr_cmtp = 38  # idpr control message transport protocol
    tp_plus_plus = 39  # tp++ transport protocol
    il = 40  # il transport protocol
    ipv6 = 41  # ipv6 encapsulation
    sdrp = 42  # source demand routing protocol
    ipv6_route = 43  # routing header for ipv6
    ipv6_frag = 44  # fragment header for ipv6
    idrp = 45  # inter_domain routing protocol
    rsvp = 46  # resource reservation protocol
    gre = 47  # generic routing encapsulation
    mhrp = 48  # mobile host routing protocol
    bna = 49  # bna
    esp = 50  # encapsulating security payload
    ah = 51  # authentication header
    i_nlsp = 52  # integrated net layer security protocol
    swipe = 53  # swipe
    narp = 54  # nbma address resolution protocol
    mobile = 55  # ip mobility (min encap)
    tlsp = 56  # transport layer security protocol (using kryptonet key management)
    skip = 57  # simple key_management for internet protocol
    ipv6_icmp = 58  # icmp for ipv6
    ipv6_nonxt = 59  # no next header for ipv6
    ipv6_opts = 60  # destination options for ipv6
    internal = 61  # any host internal protocol
    cftp = 62  # cftp
    local = 63  # any local network
    sat_expak = 64  # satnet and backroom expak
    kryptolan = 65  # kryptolan
    rvd = 66  # mit remote virtual disk protocol
    ippc = 67  # internet pluribus packet core
    distributed_file_system = 68  # any distributed file system
    sat_mon = 69  # satnet monitoring
    visa = 70  # visa protocol
    ipcv = 71  # internet packet core utility
    cpnx = 72  # computer protocol network executive
    cphb = 73  # computer protocol heart beat
    wsn = 74  # wang span network
    pvp = 75  # packet video protocol
    br_sat_mon = 76  # backroom satnet monitoring
    sun_nd = 77  # sun nd protocol_temporary
    wb_mon = 78  # wideband monitoring
    wb_expak = 79  # wideband expak
    iso_ip = 80  # international organization for standardization internet protocol
    vmtp = 81  # versatile message transaction protocol
    secure_vmtp = 82  # secure versatile message transaction protocol
    vines = 83  # vines
    ttp = 84  # ttp
    iptm = 84  # internet protocol traffic manager
    nsfnet_igp = 85  # nsfnet_igp
    dgp = 86  # dissimilar gateway protocol
    tcf = 87  # tcf
    eigrp = 88  # eigrp
    ospf = 89  # open shortest path first
    sprite_rpc = 90  # sprite rpc protocol
    larp = 91  # locus address resolution protocol
    mtp = 92  # multicast transport protocol
    ax_25 = 93  # ax.25
    ipip = 94  # ip_within_ip encapsulation protocol
    micp = 95  # mobile internetworking control protocol
    scc_sp = 96  # semaphore communications sec. pro
    etherip = 97  # ethernet_within_ip encapsulation
    encap = 98  # encapsulation header
    private_encryption = 99  # any private encryption scheme
    gmtp = 100  # gmtp
    ifmp = 101  # ipsilon flow management protocol
    pnni = 102  # pnni over ip
    pim = 103  # protocol independent multicast
    aris = 104  # ibm's aris (aggregate route ip switching) protocol
    scps = 105  # scps (space communications protocol standards)
    qnx = 106  # qnx
    a_n = 107  # active networks
    ipcomp = 108  # ip payload compression protocol
    snp = 109  # sitara networks protocol
    compaq_peer = 110  # compaq peer protocol
    ipx_in_ip = 111  # ipx in ip
    vrrp = 112  # virtual router redundancy protocol, common address redundancy protocol (not iana assigned)
    pgm = 113  # pgm reliable transport protocol
    _0_hop = 114  # any 0_hop protocol
    l2tp = 115  # layer two tunneling protocol version 3
    ddx = 116  # d_ii data exchange (ddx)
    iatp = 117  # interactive agent transfer protocol
    stp = 118  # schedule transfer protocol
    srp = 119  # spectralink radio protocol
    uti = 120  # universal transport interface protocol
    smp = 121  # simple message protocol
    sm = 122  # simple multicast protocol
    ptp = 123  # performance transparency protocol
    is_is_over_ipv4 = 124  # intermediate system to intermediate system (is_is) protocol over ipv4
    fire = 125  # flexible intra_as routing environment
    crtp = 126  # combat radio transport protocol
    crudp = 127  # combat radio user datagram
    sscopmce = 128  # service_specific connection_oriented protocol in a multilink and connectionless environment
    iplt = 129  #
    sps = 130  # secure packet shield
    pipe = 131  # private ip encapsulation within ip
    sctp = 132  # stream control transmission protocol
    fc = 133  # fibre channel
    rsvp_e2e_ignore = 134  # reservation protocol (rsvp) end_to_end ignore
    mobility_header = 135  # mobility extension header for ipv6
    udplite = 136  # lightweight user datagram protocol
    mpls_in_ip = 137  # multiprotocol label switching encapsulated in ip
    manet = 138  # manet protocols
    hip = 139  # host identity protocol
    shim6 = 140  # site multihoming by ipv6 intermediation
    wesp = 141  # wrapped encapsulating security payload
    rohc = 142  # robust header compression
    # unassigned 143-252 #
    # testing  253 - 254 # rfc 3692
    # reserved  255 #


class IpTimeToLive(object):
    # data is from http://www.howtogeek.com/104337/hacker-geek-os-fingerprinting-with-ttl-and-tcp-window-sizes/
    linux = 64
    windows = 128
    ios = 225


#     0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |Version|  IHL  |Type of Service|          Total Length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Identification        |Flags|      Fragment Offset    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Time to Live |    Protocol   |         Header Checksum       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Source Address                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Destination Address                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Options                    |    Padding    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class IpPacket(Packet):
    def __init__(self,
                 version=4,
                 header_length=5,
                 type_of_service=IpServiceType.routine,
                 total_length=None,
                 identification=0,
                 flags=0,
                 fragment_offset=0,
                 ttl=IpTimeToLive.linux,
                 protocol=IpProtocol.icmp,
                 checksum=0,
                 source_ip=0,
                 destination_ip=0,
                 payload=''):
        """
        IP Packet
        """
        self.version = version
        self.header_length = header_length
        self.type_of_service = type_of_service
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.payload = payload

    def _serialize(self):
        # IP Packet Structure http://www.networksorcery.com/enp/protocol/ip.htm

        # If the total_length left blank, let's calculate it
        if not self.total_length:
            self.total_length = self.header_length * 4 + len(self.payload)

        version_and_header_length = struct.pack('!B', (self.version << 4) | self.header_length)
        type_of_service = struct.pack('!B', self.type_of_service)
        total_length = struct.pack('!H', self.total_length)
        identification = struct.pack('!H', self.identification)
        flags = struct.pack('!H', (self.flags << 13) | self.fragment_offset)
        ttl = struct.pack('!B', self.ttl)
        protocol = struct.pack('!B', self.protocol)
        checksum = struct.pack('H', 0)

        source_ip = convert_v4_address_string_to_hex(self.source_ip)
        destination_ip = convert_v4_address_string_to_hex(self.destination_ip)

        # Data is not included in the checksum
        packet_without_checksum = version_and_header_length + \
                                  type_of_service + \
                                  total_length + \
                                  identification + \
                                  flags + \
                                  ttl + \
                                  protocol + \
                                  checksum + \
                                  source_ip + \
                                  destination_ip

        checksum = self._checksum(packet_without_checksum)
        checksum = struct.pack('H', checksum)

        payload = self.payload
        packet = version_and_header_length + \
                 type_of_service + \
                 total_length + \
                 identification + \
                 flags + \
                 ttl + \
                 protocol + \
                 checksum + \
                 source_ip + \
                 destination_ip + \
                 payload

        return packet

    def _deserialize(self, raw_packet_bytes):
        version_and_header_length = struct.unpack('B', raw_packet_bytes[0:1])[0]

        self.version = (version_and_header_length & int('11110000', 2)) >> 4
        self.header_length = (version_and_header_length & int('00001111', 2))

        self.type_of_service = struct.unpack('B', raw_packet_bytes[1:2])[0]
        self.total_length = struct.unpack('!H', raw_packet_bytes[2:4])[0]
        self.identification = struct.unpack('!H', raw_packet_bytes[4:6])[0]

        flags_and_fragment_offset = struct.unpack('!H', raw_packet_bytes[6:8])[0]
        self.flags = (flags_and_fragment_offset & int('1110000000000000', 2)) >> 13
        self.fragment_offset = (flags_and_fragment_offset & int('0001111111111111', 2))

        self.ttl = struct.unpack('B', raw_packet_bytes[8:9])[0]
        self.protocol = struct.unpack('B', raw_packet_bytes[9:10])[0]

        # Remember that checksum is not big-endian
        self.checksum = struct.unpack('H', raw_packet_bytes[10:12])[0]

        source_ip_hex = struct.unpack('!I', raw_packet_bytes[12:16])[0]
        self.source_ip = convert_v4_address_hex_to_string(source_ip_hex)

        destination_ip_hex = struct.unpack('!I', raw_packet_bytes[16:20])[0]
        self.destination_ip = convert_v4_address_hex_to_string(destination_ip_hex)

        self.payload = raw_packet_bytes[20:]


# --==-- ==--== ==---== --==-- ==--== ==---== --==-- ==--== ==---== --==-- ==--== ==---==
# Transmission Control Protocol (TCP) :

#     0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |          Source Port          |       Destination Port        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        Sequence Number                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Acknowledgment Number                      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Data |           |U|A|P|R|S|F|                               |
#   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
#   |       |           |G|K|H|T|N|N|                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           Checksum            |         Urgent Pointer        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Options                    |    Padding    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                             data                              |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class TcpPacket(Packet):
    def __init__(self,
                 source_ip=None,
                 destination_ip=None,
                 protocol=None,
                 source_port=0,
                 destination_port=0,
                 sequence_number=123,
                 ack_number=0,
                 data_offset=5,
                 fin=False,
                 syn=False,
                 rst=False,
                 psh=False,
                 ack=False,
                 urg=False,
                 window_size=53270,
                 checksum=0,
                 urgent_pointer=0,
                 options=None,
                 payload=''):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.source_port = source_port
        self.destination_port = destination_port
        self.sequence_number = sequence_number
        self.ack_number = ack_number
        self.data_offset = data_offset
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.psh = psh
        self.ack = ack
        self.urg = urg
        self.window_size = window_size
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer
        self.options = options
        self.payload = payload

    def _serialize(self):
        # TCP Packet Structure http://en.wikipedia.org/wiki/Transmission_Control_Protocol

        # Why pseudo header for checksum calculation?
        # Read more http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm

        # --==-- --==--
        # Options

        if not self.options:
            # Create the default options

            self.options = \
                struct.pack('!BBH', 2, 4, 1460) + \
                struct.pack('!BB', 4, 2) + \
                struct.pack('!BBII', 8, 10, 63022427, 0) + \
                struct.pack('!B', 1) + \
                struct.pack('!BBB', 3, 3, 7)

        options_length_in_bytes = len(self.options)
        options_length_with_padding_in_bytes = (i for i in range(0, 140, 4) if i >= options_length_in_bytes).next()

        if options_length_with_padding_in_bytes > options_length_in_bytes:
            self.options += '\000' * (options_length_with_padding_in_bytes - options_length_in_bytes)

        options_length_with_padding_in_words = options_length_with_padding_in_bytes / 4

        data_offset = (((self.data_offset + options_length_with_padding_in_words) << 4) | 0)

        # --==-- --==--
        # Pseudo Header

        flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)

        tcp_header = struct.pack('!HHIIBBHHH',
                                 self.source_port,
                                 self.destination_port,
                                 self.sequence_number,
                                 self.ack_number,
                                 data_offset,
                                 flags,
                                 self.window_size,
                                 0,
                                 self.urgent_pointer) + self.options

        tcp_header_length = len(tcp_header) + len(self.payload)

        pseudo_header = convert_v4_address_string_to_hex(self.source_ip) + \
                        convert_v4_address_string_to_hex(self.destination_ip) + \
                        struct.pack('!BBH', 0, self.protocol, tcp_header_length)

        packet_to_checksum = pseudo_header + tcp_header + self.payload

        # --==-- --==--
        # The actual Packet

        checksum = self._checksum(packet_to_checksum)

        packet_with_checksum = struct.pack('!HHIIBBH',
                                           self.source_port,
                                           self.destination_port,
                                           self.sequence_number,
                                           self.ack_number,
                                           data_offset,
                                           flags,
                                           self.window_size) + \
                               struct.pack('H', checksum) + \
                               struct.pack('!H', self.urgent_pointer) + self.options

        packet = packet_with_checksum + self.payload

        return packet

    def _deserialize(self, raw_packet_bytes):

        self.source_port = struct.unpack('!H', raw_packet_bytes[0:2])[0]
        self.destination_port = struct.unpack('!H', raw_packet_bytes[2:4])[0]
        self.sequence_number = struct.unpack('!I', raw_packet_bytes[4:8])[0]
        self.ack_number = struct.unpack('!I', raw_packet_bytes[8:12])[0]
        self.data_offset = (struct.unpack('!B', raw_packet_bytes[12:13])[0] & int('11110000', 2)) >> 4

        flags = struct.unpack('!B', raw_packet_bytes[13:14])[0]
        self.fin = (flags & int('00000001', 2)) != 0
        self.syn = (flags & int('00000010', 2)) != 0
        self.rst = (flags & int('00000100', 2)) != 0
        self.psh = (flags & int('00001000', 2)) != 0
        self.ack = (flags & int('00010000', 2)) != 0
        self.urg = (flags & int('00100000', 2)) != 0

        self.window_size = struct.unpack('!H', raw_packet_bytes[14:16])[0]

        # Checksum is little endian (no !)
        self.checksum = struct.unpack('H', raw_packet_bytes[16:18])[0]

        self.urgent_pointer = struct.unpack('!H', raw_packet_bytes[18:20])[0]

        if self.data_offset > 5:
            options_start = 20
            options_end = self.data_offset * 4
            self.options = raw_packet_bytes[options_start:options_end]
            self.payload = raw_packet_bytes[options_end:]
        else:
            self.payload = raw_packet_bytes[20:]


# --==-- ==--== ==---== --==-- ==--== ==---== --==-- ==--== ==---== --==-- ==--== ==---==
# User Datagram Protocol (UDP) :


#  0      7 8     15 16    23 24    31
#  +--------+--------+--------+--------+
#  |     Source      |   Destination   |
#  |      Port       |      Port       |
#  +--------+--------+--------+--------+
#  |                 |                 |
#  |     Length      |    Checksum     |
#  +--------+--------+--------+--------+
#  |
#  |          data octets ...
#  +---------------- ...


class UdpPacket(Packet):
    def __init__(self,
                 source_ip=None,
                 destination_ip=None,
                 protocol=None,
                 source_port=0,
                 destination_port=0,
                 length=0,
                 checksum=0,
                 payload=''):
        self.source_port = source_port
        self.destination_port = destination_port
        self.length = length
        self.checksum = checksum
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.payload = ''

    def _serialize(self):

        self.length = 8 + len(self.payload)

        pseudo_header = convert_v4_address_string_to_hex(self.source_ip) + \
                        convert_v4_address_string_to_hex(self.destination_ip) + \
                        struct.pack('!BBH',
                                    0,
                                    self.protocol,
                                    self.length)

        udp_header = struct.pack('!HHHH',
                                 self.source_port,
                                 self.destination_port,
                                 self.length,
                                 0)

        packet_to_checksum = pseudo_header + udp_header

        self.checksum = self._checksum(packet_to_checksum)

        packet = struct.pack('!HHH',
                             self.source_port,
                             self.destination_port,
                             self.length) + \
                 struct.pack('H', self.checksum) + \
                 self.payload

        return packet

    def _deserialize(self, raw_packet_bytes):
        self.source_port = struct.unpack('!H', raw_packet_bytes[0:2])[0]
        self.destination_port = struct.unpack('!H', raw_packet_bytes[2:4])[0]
        self.length = struct.unpack('!H', raw_packet_bytes[4:6])[0]
        self.checksum = struct.unpack('!H', raw_packet_bytes[6:8])[0]


