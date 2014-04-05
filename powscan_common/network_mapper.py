import abc
import logging
from networking_helper import *
from powscan_common.packet_helper import *

__author__ = 'Jossef Harush'


class NetworkMapper(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, include_empty_responses=False, skip_ip_addresses=[], timeout=0.5):
        self.include_empty_responses = include_empty_responses
        self.skip_ip_addresses = skip_ip_addresses
        self.timeout = timeout

    def _map_all_interfaces(self, include_loopback=False):
        # Map all interface (except loopback)
        interfaces = get_interfaces()

        for interface in interfaces:

            interface_ip_address = interface[1]
            interface_subnet_mask = interface[3]

            if interface_ip_address == '127.0.0.1' or include_loopback:
                continue

            items = self._map_interface(interface_ip_address, interface_subnet_mask)

            # re-yielding the items in order to be transparent to public 'map' callers
            for item in items:
                yield item

    def _map_interface(self, interface_ip_address, interface_subnet_mask):
        """
        Maps the interface
        calling _map for each endpoint address in the given interface address + mask
        """
        endpoint_addresses = get_network_endpoint_addresses(interface_ip_address, interface_subnet_mask)
        for endpoint_address in endpoint_addresses:

            # If the current endpoint address is in the skip list, ignore it.
            if endpoint_address in self.skip_ip_addresses:
                continue

            result = self._map(interface_ip_address, endpoint_address)

            # If the result is None - don't yield by default
            # If self.include_empty_responses is True, always include
            if result or self.include_empty_responses:
                yield result


    def map(self, interface_ip_address=None, interface_subnet_mask=None, include_loopback=False):
        """
        map all the hosts in subnet

        when interface_ip_address and  subnet is None,
            we enumerate the local interfaces and perform the mapping login for each interface
            * note: by default the loopback interface is being ignored.
                    in case you would like to change this behavior,
                    set True in 'include_loopback'

        when interface_ip_address is valid but subnet is None,
            we enumerate the local interfaces to match a suitable subnet

        """
        # If ip was not provided
        if not interface_ip_address:
            # let's do this for all interfaces
            return self._map_all_interfaces(include_loopback)

        # IP provided but mac is missing
        if not interface_subnet_mask:
            # let's find the suitable mac:
            interfaces = get_interfaces()

            for item in interfaces:

                current_ip_address = item[1]
                current_subnet = item[3]

                if interface_ip_address == current_ip_address:
                    interface_subnet_mask = current_subnet
                    break

            # If we didn't find the given ip address in the interfaces list
            if not interface_subnet_mask:
                raise Exception('interface {0} was not found'.format(interface_ip_address))

        return self._map_interface(interface_ip_address, interface_subnet_mask)


    @abc.abstractmethod
    def _map(self, interface_ip_address, destination_ip_address):
        pass


class IcmpNetworkMapper(NetworkMapper):
    def _map(self, interface_ip_address, destination_ip_address):

        sock = None
        try:
            icmp_packet = IcmpPacket(

                type=IcmpType.echo,
                # id=os.getpid() & 0xFFFF
            )

            icmp_data = icmp_packet.serialize()


            sock = create_icmp_socket()

            port = 0


            timeout_in_seconds = self.timeout / 1000

            response, addr = socket_send_receive(sock,
                                                 icmp_data,
                                                 destination_ip_address,
                                                 port,
                                                 timeout_in_seconds=timeout_in_seconds)

            ip_packet = IpPacket()
            ip_packet.deserialize(response)

            return ip_packet.source_ip
        # Exception may be thrown if timeout or communication error
        # We ignoring it purposely and logging it
        except Exception as ex:
            logging.debug(ex)
            return None

        finally:
            # Close the socket
            if sock:
                sock.close()
