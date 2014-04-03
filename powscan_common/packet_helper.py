import os
import struct
import array
import struct
from socket import htons, ntohs
from powscan_common.networking_helper import convert_v4_address_string_to_bits

__author__ = 'Jossef Harush'
import abc


class Packet(object):
    __metaclass__ = abc.ABCMeta

    def _validate_checksum(self, raw_packet_bytes):
        """
            Validates the given raw_packet_bytes
            raises ValueError if invalid checksum
        """
        checksum_result = self._checksum(raw_packet_bytes)

        # result should be 0 if valid
        if checksum_result != 0:
            raise ValueError('Checksum mismatch')

    def _checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            c = s + w
            s = (c & 0xffff) + (c >> 16)
        return ~s & 0xffff

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
    def __init__(self, type=IcmpType.echo, code=0, id=None, sequence=0, data='Power Scanner ICMP'):
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

        packet_without_checksum = type + \
                                  code + \
                                  checksum_result + \
                                  id + \
                                  sequence + \
                                  self.data

        checksum_result = self._checksum(packet_without_checksum)
        checksum_result = struct.pack('H', checksum_result)

        packet = type + \
                 code + \
                 checksum_result + \
                 id + \
                 sequence + \
                 self.data

        return packet

    def _deserialize(self, raw_packet_bytes):
        self.type = ord(raw_packet_bytes[0])
        self.code = ord(raw_packet_bytes[1])
        elts = struct.unpack('HHH', raw_packet_bytes[2:8])
        cksum = 0
        [cksum, self.id, self.sequence] = map(lambda x: x & 0xffff, elts)
        self.data = raw_packet_bytes[8:]


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


class IpPacket(Packet):
    def __init__(self,

                 # 4 bits
                 version=4,

                 # 4 bits
                 header_length=5,

                 # 8 bits
                 type_of_service=IpServiceType.routine,

                 # 16 bits
                 total_length=None,

                 # 16 bits
                 identification=0,

                 # 3 bits
                 flags=IpFlags.fragment_if_necessary,

                 # 13 bits
                 fragment_offset=0,

                 # 8 bits
                 ttl=IpTimeToLive.linux,

                 # 8 bits
                 protocol=IpProtocol.icmp,

                 # 16 bits
                 checksum=0,

                 # 32 bits
                 source_ip=0,

                 # 32 bits
                 destination_ip=0,

                 # variable
                 data=''):
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
        self.data = data

    def _serialize(self):
        # IP Packet Structure http://www.networksorcery.com/enp/protocol/ip.htm

        # If the total_length left blank, let's calculate it
        if not self.total_length:
            self.total_length = self.header_length * 4 + len(self.data)

        version_and_header_length = struct.pack('B', (self.version << 4) | self.header_length)
        type_of_service = struct.pack('B', self.type_of_service)
        total_length = struct.pack('H', self.total_length)
        identification = struct.pack('H', self.identification)
        flags = struct.pack('H', (self.flags << 13) | self.fragment_offset)
        ttl = struct.pack('B', self.ttl)
        protocol = struct.pack('B', self.protocol)
        checksum = struct.pack('H', 0)

        source_ip_bits = convert_v4_address_string_to_bits(self.source_ip)
        source_ip = struct.pack('L', int(source_ip_bits, 2))

        destination_ip_bits = convert_v4_address_string_to_bits(self.destination_ip)
        destination_ip = struct.pack('L', int(destination_ip_bits, 2))

        data = self.data

        packet_without_checksum = version_and_header_length + \
                                  type_of_service + \
                                  total_length + \
                                  identification + \
                                  flags + \
                                  ttl + \
                                  protocol + \
                                  checksum + \
                                  source_ip + \
                                  destination_ip + \
                                  data

        checksum = self._checksum(packet_without_checksum)
        checksum = struct.pack('H', checksum)

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
                 data

        return packet

    def _deserialize(self, raw_packet_bytes):
        pass


# -- == -- =-- == -- =-- == -- =-- == -- =-- == -- =
# Helper methods taken from an open source 'pinger'
# written by Jeremy Hylton, jeremy@cnri.reston.va.us


#
#
# def cksum(s):
#     if len(s) & 1:
#         s = s + '\0'
#     words = array.array('h', s)
#     sum = 0
#     for word in words:
#         sum = sum + (word & 0xffff)
#     hi = sum >> 16
#     lo = sum & 0xffff
#     sum = hi + lo
#     sum = sum + (sum >> 16)
#     return (~sum) & 0xffff
#
#
# # Should generalize from the *h2net patterns
#
# # This python code is suboptimal because it is based on C code where
# # it doesn't cost much to take a raw buffer and treat a section of it
# # as a u_short.
#
# def gets(s):
#     return struct.unpack('h', s)[0] & 0xffff
#
#
# def mks(h):
#     return struct.pack('H', h)
#
#
# def iph2net(s):
#     len = htons(gets(s[2:4]))
#     id = htons(gets(s[4:6]))
#     off = htons(gets(s[6:8]))
#     return s[:2] + mks(len) + mks(id) + mks(off) + s[8:]
#
#
# def net2iph(s):
#     len = ntohs(gets(s[2:4]))
#     id = ntohs(gets(s[4:6]))
#     off = ntohs(gets(s[6:8]))
#     return s[:2] + mks(len) + mks(id) + mks(off) + s[8:]
#
#
# def udph2net(s):
#     sp = htons(gets(s[0:2]))
#     dp = htons(gets(s[2:4]))
#     len = htons(gets(s[4:6]))
#     return mks(sp) + mks(dp) + mks(len) + s[6:]
#
#
# def net2updh(s):
#     sp = ntohs(gets(s[0:2]))
#     dp = ntohs(gets(s[2:4]))
#     len = ntohs(gets(s[4:6]))
#     return mks(sp) + mks(dp) + mks(len) + s[6:]

