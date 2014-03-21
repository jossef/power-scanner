import argparse
import re

__author__ = 'jossef'


def main():
    parser = argparse.ArgumentParser(description='Pyscan - TASK 2 - Building Scanning tool')

    parser.add_argument('-ip', dest='ip_address', metavar='IP', help='target ip address', required=True)
    parser.add_argument('-t', dest='time_interval', metavar='TIME', type=int,
                        help='time interval between each scan in milliseconds', required=True)
    parser.add_argument('-pt', dest='protocol_type', metavar='PROTOCOL', choices=['UDP', 'TCP', 'ICMP'],
                        help='protocol type [UDP/TCP/ICMP]', required=True)
    parser.add_argument('-p', dest='ports', metavar='PORT', nargs='+',
                        help='ports [ can be range : -p 22-54 , can be single port : -p 80 , can be combination (space separated) : -p 80 43 23 125]',
                        required=True)
    parser.add_argument('-type', dest='scan_type', metavar='TYPE', choices=['full', 'stealth', 'fin', 'ack'],
                        help='scan type [full,stealth,fin,ack]', required=True)
    parser.add_argument('-b', dest='grab_banner', action='store_true',
                        help='bannerGrabber status (Should work only for TCP)')

    args = parser.parse_args()

    port_regex = re.compile(
        "^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])-([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$|^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$")

    grab_banner = args.grab_banner
    ip_address = args.ip_address
    time_interval = args.time_interval
    protocol_type = args.protocol_type
    scan_type = args.scan_type
    ports = []

    try:
        # --== ==-- --== ==--
        # Parse the port ranges
        for item in args.ports:
            if not port_regex.match(item):
                raise Exception('Port should be number or number range i.e. "x" or "x-y". got {0}'.format(item))

            # Port range i.e. a-b
            if '-' in item:

                split = item.split('-')
                item1 = int(split[0])
                item2 = int(split[1])

                if item1 == item2:
                    ports.append(int(item1))
                elif item1 < item2:
                    for port in range(item1, item2 + 1):
                        ports.append(int(port))
                else:
                    for port in range(item2, item1 + 1):
                        ports.append(int(port))

            # Single port
            else:
                ports.append(int(item))

        # Remove duplicates
        ports = list(set(ports))

        print ports

    except Exception as ex:
        print 'Arguments parse error: {0}'.format(ex)
        parser.print_help()

    # --== ==-- --== ==--


if __name__ == "__main__":
    main()
