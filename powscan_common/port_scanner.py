from powscan_common.packet_helper import IcmpPacket

__author__ = 'Jossef Harush'
import abc
import socket
import logging

from socket_helper import *
from banner_helper import *
import time


class PortScanner(object):
    __metaclass__ = abc.ABCMeta

    # TODO change default sleep value
    def __init__(self, address, ports=range(1, 65535), sleep_in_milliseconds=100):
        self.address = address
        self.ports = ports
        self.sleep_in_milliseconds = sleep_in_milliseconds

    def scan(self):
        for port in self.ports:
            yield self._scan(port)

            # Sleep for each iteration
            time.sleep(self.sleep_in_milliseconds / 1000.0)

    @abc.abstractmethod
    def _scan(self, port):
        """
        port - port to scan
        """

        pass


class FullTcpScanner(PortScanner):
    def _scan(self, port):
        """

        """
        icmp_packet = IcmpPacket()
        socket_transmit(icmp_packet, self.address,)

        return 'scanning tcp {0}'.format(port)


class UdpScanner(PortScanner):
    def _scan(self, port):
        """
        """
        pass


class AckScanner(PortScanner):
    def _scan(self, port):
        """
        """
        pass


class StealthScanner(PortScanner):
    def _scan(self, port):
        """
        """
        pass


class FinScanner(PortScanner):
    def _scan(self, port):
        """
        """
        pass