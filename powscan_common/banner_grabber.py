__author__ = 'Jossef Harush'
import abc
import socket
import logging

from socket_helper import *
from banner_helper import *


class BannerGrabber(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, address, port):
        self.address = address
        self.port = port

    @staticmethod
    def create(address, port):
        """
         Factory method for inheritors
        """
        if port == 80:
            return HttpBannerGrabber(address, port)

        if port == 25:
            return SmtpBannerGrabber(address, port)

        if port == 21:
            return FtpBannerGrabber(address, port)

        raise Exception('Given port - {0} is not supported with this factory method'.format(port))

    def get_banner(self):
        """
        returns <server>, <operating_system>, <port>
        <server>, <operating_system> may be null if N/A
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_connect(sock, self.address, self.port)

            # Optional "Handshake" - sends something before receive
            self._handshake(sock)

            # Receive the banner
            banner = socket_receive(sock)

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


class HttpBannerGrabber(BannerGrabber):
    def _handshake(self, sock):
        # In HTTP - First the client should send:
        #      HEAD / HTTP/1.1\r\nHost: <HOST_ADDRESS>\r\n\r\n
        # in order to grab the banner

        sock.send("HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % self.address)

    def _parse_banner(self, banner):
        operating_system = None
        server = None

        # Lets Search for the 'Server: ' instance
        banner_lines = banner.split('\n')
        banner_lines = [item.strip() for item in banner_lines]

        server_prefix = 'server:'
        server_line = (item for item in banner_lines if item.lower().startswith(server_prefix)).next()
        if server_line:
            server_line = server_line[len(server_prefix):].strip()

            server, operating_system = get_http_banner_info(server_line)

        return server, operating_system


class SmtpBannerGrabber(BannerGrabber):
    def _handshake(self, sock):
        # left blank purposely - no need for handshake in SMTP
        pass

    def _parse_banner(self, banner):

        operating_system = None
        server = None

        # Lets scrape for any hints
        banner_lines = banner.split('\n')
        banner_lines = [item.strip() for item in banner_lines]

        for banner_line in banner_lines:
            server, operating_system = get_smtp_banner_info(banner_line)
            if server or operating_system:
                break

        return server, operating_system


class FtpBannerGrabber(BannerGrabber):
    def _handshake(self, sock):
        # left blank purposely - no need for handshake in FTP
        pass

    def _parse_banner(self, banner):

        operating_system = None
        server = None

        # Lets scrape for any hints
        banner_lines = banner.split('\n')
        banner_lines = [item.strip() for item in banner_lines]

        for banner_line in banner_lines:
            server, operating_system = get_ftp_banner_info(banner_line)
            if server or operating_system:
                break

        return server, operating_system