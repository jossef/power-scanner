__author__ = 'Jossef Harush'

from powscan_common.packet_helper import *
import abc
import socket
import logging
from networking_helper import *
from banner_helper import *
import time


class PortScanner(object):
    __metaclass__ = abc.ABCMeta

    @staticmethod
    def create(type,
               source_ip,
               destination_ip,
               sleep_in_milliseconds,
               timeout_im_milliseconds,
               ports):
        """
         Factory method for inheritors
        """
        if type == 'full_tcp':
            return FullTcpScanner(source_ip=source_ip,
                                  ports=ports,
                                  timeout_im_milliseconds=timeout_im_milliseconds,
                                  destination_ip=destination_ip,
                                  sleep_in_milliseconds=sleep_in_milliseconds)

        if type == 'udp':
            return UdpScanner(source_ip=source_ip,
                              ports=ports,
                              timeout_im_milliseconds=timeout_im_milliseconds,
                              destination_ip=destination_ip,
                              sleep_in_milliseconds=sleep_in_milliseconds)

        if type == 'ack':
            return AckScanner(source_ip=source_ip,
                              ports=ports,
                              timeout_im_milliseconds=timeout_im_milliseconds,
                              destination_ip=destination_ip,
                              sleep_in_milliseconds=sleep_in_milliseconds)

        if type == 'fin':
            return FinScanner(source_ip=source_ip,
                              ports=ports,
                              timeout_im_milliseconds=timeout_im_milliseconds,
                              destination_ip=destination_ip,
                              sleep_in_milliseconds=sleep_in_milliseconds)

        if type == 'stealth':
            return StealthScanner(source_ip=source_ip,
                                  ports=ports,
                                  timeout_im_milliseconds=timeout_im_milliseconds,
                                  destination_ip=destination_ip,
                                  sleep_in_milliseconds=sleep_in_milliseconds)

        raise Exception('Given type - {0} is not supported with this factory method'.format(type))

    def __init__(self,
                 destination_ip=None,
                 ports=range(1, 65535),
                 sleep_in_milliseconds=100,
                 timeout_im_milliseconds=350,
                 source_ip=None):
        self.destination_ip = destination_ip
        self.ports = ports
        self.sleep_in_milliseconds = sleep_in_milliseconds
        self.timeout_im_milliseconds = timeout_im_milliseconds
        self.source_ip = source_ip

    def scan(self):
        for port in self.ports:
            try:
                yield self._scan(port)
            except Exception as ex:
                logging.debug(ex)

            # Sleep for each iteration (as instructed)
            # We are dividing by 1000 because time.sleep gets expect time in seconds
            time.sleep(self.sleep_in_milliseconds / 1000.0)

    @abc.abstractmethod
    def _scan(self, port):
        """
        port - port to scan
        """

        pass


class FullTcpScanner(PortScanner):
    def _scan(self, port):
        sock = None
        try:

            # IMPORTANT NOTE:
            # **************

            # After implemented TCP/IP handshake protocol i discovered a known issue:
            #
            # linux's kernel is sending a RST when receiving a SYN-ACK packet
            # Took me some time to discover it ...
            # For more info please read:
            #   http://www.packetlevel.ch/html/scapy/scapy3way.html
            #   http://stackoverflow.com/questions/9058052/unwanted-rst-tcp-packet-with-scapy/9154940#9154940
            #   http://www.opensourceforu.com/2011/10/syn-flooding-using-scapy-and-prevention-using-iptables/

            # Flow:
            #   Sending SYN -> success
            #   Receiving SYN/ACK -> success
            #   Kernel is sending RST -> unwanted behavior

            # In order to workaround this issue i can:
            #   1. modify iptables with specific rules that change this behavior
            #   2. use socket.connect() which does all of the tcp handshake syn->syn-ack->ack in the background

            # Because i don't want to modify iptables, i continued with socket.connect() .


            sock = socket.socket()

            timeout_in_seconds = self.timeout_im_milliseconds / 1000
            sock.settimeout(timeout_in_seconds)

            sock.connect((self.destination_ip, port))

            # If we are in this line, port is open
            # Otherwise exception has been thrown

            return port

        finally:
            # Close the socket
            if sock:
                sock.close()


class UdpScanner(PortScanner):
    def _scan(self, port):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock = create_udp_socket()
            sock.settimeout(self.timeout_im_milliseconds / 1000)
            zero_packet_payload = '\0x00'

            source_ip = self.source_ip

            sock.bind(('', 0))
            reply_port = sock.getsockname()[1]

            timeout_in_seconds = self.timeout_im_milliseconds / 1000
            sock.settimeout(timeout_in_seconds)

            # --==-- ==--== ==--==
            # SEND UDP

            udp_packet = UdpPacket(protocol=IpProtocol.udp,
                                   source_ip=source_ip,
                                   source_port=reply_port,
                                   destination_ip=self.destination_ip,
                                   destination_port=port,
                                   payload=zero_packet_payload)
            udp_data = udp_packet.serialize()

            sock.sendto(udp_data, (self.destination_ip, port))

            # --==-- ==--== ==--==
            # EXPECT ICMP Unreachable

            # while true or timeout
            while True:

                udp_response = ''

                try:
                    udp_response = sock.recvfrom(65535)[0][0:]
                except socket.timeout:
                    # Timeout - Assume open / filtered
                    return port

                ip_packet = IpPacket()
                ip_packet.deserialize(udp_response)
                if ip_packet.destination_ip == source_ip and ip_packet.source_ip == self.destination_ip:
                    break


            # Let's parse the response
            icmp_packet = IcmpPacket()
            icmp_packet.deserialize(ip_packet.payload)

            if icmp_packet.type == IcmpType.unreach or \
                            icmp_packet.type == IcmpType.unreach_needfrag or \
                            icmp_packet.type == IcmpType.unreach_port or \
                            icmp_packet.type == IcmpType.unreach_net or \
                            icmp_packet.type == IcmpType.unreach_srcfail or \
                            icmp_packet.type == IcmpType.unreach_protocol or \
                            icmp_packet.type == IcmpType.unreach_host:
                raise Exception('port is closed')

            return port

        finally:
            # Close the socket
            if sock:
                sock.close()


class AckScanner(PortScanner):
    def _scan(self, port):

        sock = None
        try:

            sock = create_tcp_socket()

            timeout_in_seconds = self.timeout_im_milliseconds / 1000
            sock.settimeout(timeout_in_seconds)

            source_ip = self.source_ip
            sock.bind(('', 0))
            reply_port = sock.getsockname()[1]

            payload = ''

            # --==-- ==--== ==--==
            # SEND ACK

            tcp_packet = TcpPacket(protocol=IpProtocol.tcp,
                                   destination_ip=self.destination_ip,
                                   source_ip=source_ip,
                                   source_port=reply_port,
                                   sequence_number=512,
                                   destination_port=port,
                                   ack=True,
                                   payload=payload)
            tcp_data = tcp_packet.serialize()

            ip_packet = IpPacket(protocol=IpProtocol.tcp,
                                 destination_ip=self.destination_ip,
                                 source_ip=source_ip,
                                 flags=IpFlags.dont_fragment,
                                 identification=54321,
                                 payload=tcp_data)

            packet = ip_packet.serialize()

            sock.sendto(packet, (self.destination_ip, 0))


            # --==-- ==--== ==--==
            # EXPECT RST

            # while true or timeout
            while True:
                response = sock.recvfrom(65535)[0][0:]
                ip_packet = IpPacket()
                ip_packet.deserialize(response)
                if ip_packet.destination_ip == source_ip and ip_packet.source_ip == self.destination_ip:
                    break

            tcp_packet = TcpPacket()
            tcp_packet.deserialize(ip_packet.payload)
            if tcp_packet.rst:
                return port

        finally:
            # Close the socket
            if sock:
                sock.close()


class StealthScanner(PortScanner):
    def _scan(self, port):
        sock = None
        try:

            timeout_in_seconds = self.timeout_im_milliseconds / 1000
            sock = create_tcp_socket()
            sock.settimeout(timeout_in_seconds)

            source_ip = self.source_ip

            sock.bind(('', 0))
            reply_port = sock.getsockname()[1]

            payload = ''


            # --==-- ==--== ==--==
            # SEND SYN

            tcp_packet = TcpPacket(protocol=IpProtocol.tcp,
                                   destination_ip=self.destination_ip,
                                   source_ip=source_ip,
                                   source_port=reply_port,
                                   sequence_number=512,
                                   destination_port=port,
                                   syn=True,
                                   payload=payload)
            tcp_data = tcp_packet.serialize()

            ip_packet = IpPacket(protocol=IpProtocol.tcp,
                                 destination_ip=self.destination_ip,
                                 source_ip=source_ip,
                                 flags=IpFlags.dont_fragment,
                                 identification=54321,
                                 payload=tcp_data)

            packet = ip_packet.serialize()

            sock.sendto(packet, (self.destination_ip, 0))


            # --==-- ==--== ==--==
            # RECEIVE SYN-ACK

            # while true or timeout
            while True:
                response = sock.recvfrom(65535)[0][0:]
                ip_packet = IpPacket()
                ip_packet.deserialize(response)
                if ip_packet.destination_ip == source_ip and ip_packet.source_ip == self.destination_ip:
                    break


            # Let's parse the response

            tcp_packet = TcpPacket()
            tcp_packet.deserialize(ip_packet.payload)

            # Check if syn-ack flags are on

            if not tcp_packet.syn or not tcp_packet.ack:
                raise Exception('expected syn-ack. invalid handshake')

            # K - port is open
            # Returning the port gonna close the session (finally scope)
            return port

        finally:
            # Close the socket
            if sock:
                sock.close()


class FinScanner(PortScanner):
    def _scan(self, port):
        sock = None
        try:

            timeout_in_seconds = self.timeout_im_milliseconds / 1000
            sock = create_tcp_socket()
            sock.settimeout(timeout_in_seconds)

            source_ip = self.source_ip

            sock.bind(('', 0))
            reply_port = sock.getsockname()[1]

            payload = ''


            # --==-- ==--== ==--==
            # SEND FIN

            tcp_packet = TcpPacket(protocol=IpProtocol.tcp,
                                   destination_ip=self.destination_ip,
                                   source_ip=source_ip,
                                   source_port=reply_port,
                                   sequence_number=512,
                                   destination_port=port,
                                   fin=True,
                                   payload=payload)
            tcp_data = tcp_packet.serialize()

            ip_packet = IpPacket(protocol=IpProtocol.tcp,
                                 destination_ip=self.destination_ip,
                                 source_ip=source_ip,
                                 flags=IpFlags.dont_fragment,
                                 identification=54321,
                                 payload=tcp_data)

            packet = ip_packet.serialize()

            sock.sendto(packet, (self.destination_ip, 0))


            # --==-- ==--== ==--==
            # EXPECT NO RST

            # while true or timeout
            while True:
                response = sock.recvfrom(65535)[0][0:]
                ip_packet = IpPacket()
                ip_packet.deserialize(response)
                if ip_packet.destination_ip == source_ip and ip_packet.source_ip == self.destination_ip:
                    break


            # Let's parse the response

            tcp_packet = TcpPacket()
            tcp_packet.deserialize(ip_packet.payload)

            # Check if rst flag is on

            if tcp_packet.rst:
                raise Exception('expected rst. invalid handshake')

            # K - port is open
            # Returning the port gonna close the session (finally scope)
            return port

        finally:
            # Close the socket
            if sock:
                sock.close()
