__author__ = 'Jossef Harush'
import abc
import socket
import logging

from socket_helper import *
from banner_helper import *


class PortScanner(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, address, ports=range(1, 65535)):
        self.address = address
        self.ports = ports


    def scan(self):
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_connect(sock, self.address, self.port)

            # Optional "Handshake" - sends something before receive
            self._handshake(sock)

            # Receive the banner
            banner = socket_recieve(sock)

            # Parse the bustard
            server, operating_system = self._parse_banner(banner)

            return server, operating_system, self.port

        except Exception as ex:
            # Log exception in debug mode
            logging.debug(ex)

            return None, None, self.port

        finally:
            if sock:
                sock.close()


    @abc.abstractmethod
    def _handshake(self, sock):
        """
        sock - the opened socket
        the inheritor should implement his protocol's relevant behavior
        for instance, in http: sends HEAD / HTTP ... and then waits for response / timeout
        on the other hand on other protocols such as smtp, the server sends his banner on connection
        """
        pass

    @abc.abstractmethod
    def _parse_banner(self, banner):
        """Should handle the parse of the banner and return <server>, <operating_system>"""
        pass


