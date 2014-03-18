import argparse

__author__ = 'jossef'


def main():
    parser = argparse.ArgumentParser(description='Pyscan - TASK 2 - Building Scanning tool')

    parser.add_argument('-ip', metavar='IP', help='target ip address', required=True)
    parser.add_argument('-t', metavar='TIME', type=int, help='time interval between each scan in milliseconds', required=True)
    parser.add_argument('-pt', metavar='PROTOCOL', choices=['UDP', 'TCP', 'ICMP'], help='protocol type [UDP/TCP/ICMP]', required=True)
    parser.add_argument('-p', metavar='PORT',  nargs='+', help='ports [ can be range : -p 22-54 , can be single port : -p 80 , can be combination (space separated) : -p 80 43 23 125]', required=True)
    parser.add_argument('-type', metavar='TYPE', choices=['full', 'stealth', 'fin', 'ack'], help='scan type [full,stealth,fin,ack]', required=True)
    parser.add_argument('-b', action='store_true', help='bannerGrabber status (Should work only for TCP)')

    args = parser.parse_args()

    try:
        # Parse the special values (port range)
        ip_address = args.ip
        time_interval = args.t
        protocol_type = args.pt
        ports = []
        for item in args.p:
            # Max one '-'
            # Range 'a-b' Handling
            pass

    except Exception as ex:
        print ex
        parser.print_help()

if __name__ == "__main__":
    main()
