import abc

__author__ = 'Jossef Harush'


class NetworkMapper(object):
    __metaclass__ = abc.ABCMeta

    def map(self, interface_ip_address=None, subnet=None):
        """
        map all the hosts in subnet

        when interface_ip_address and  subnet is None,
        we enumerate the local interfaces and perform the mapping login for each interface

        when interface_ip_address is valid but subnet is None,
        we enumerate the local interfaces to match a suitable subnet

        """

        if interface_ip_address is None:
            # Map all interface
            pass

        # Ip address provided but mac is missing. let's find the suitable mac
        elif subnet is None:
            pass

        # Both
        else:
            pass


        @abc.abstractmethod
        def _map(self, ip_address, subnet):
            pass


class IcmpNetworkMapper(NetworkMapper):
    def _map(self, ip_address, subnet):

        if not ip_address:
            raise ValueError("argument 'ip_address' is None")

        if not subnet:
            raise ValueError("argument 'subnet' is None")

        pass