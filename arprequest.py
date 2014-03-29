#!/usr/bin/env python
#By s3my0n

#############################################################################
# ftpcheck.py                                                               #
#                                                                           #
# Takes a list of server addresses and checks if the name of                #
# their ftp servers match with the ftp server you are looking for.          #
#                                                                           #
# Copyright (C) 2009  s3my0n                                                #
#                                                                           #
# This program is free software: you can redistribute it and/or modify      #
# it under the terms of the GNU General Public License as published by      #
# the Free Software Foundation, either version 3 of the License, or         #
# any later version.                                                        #
#                                                                           #
# This program is distributed in the hope that it will be useful,           #
# but WITHOUT ANY WARRANTY; without even the implied warranty of            #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                              #
#                                                                           #
# You should have received a copy of the GNU General Public License         #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.     #    
#############################################################################

from ftplib import FTP
import re, sys

class FtpCheck(object):
    def __init__(self, LIST, VERBOSE, BANNER):
        self.banner = BANNER
        self.list = LIST
        self.verbose = VERBOSE

        self.slist = list(s.replace('\n', '') for s in LIST)
        for s in self.slist:
            s.strip()
            try:
                self.slist.remove('')
            except ValueError:
                pass
        
    def Check(self, TIMEOUT):
        self.matchlist = []
        self.error = False
        for IP in self.slist:
            try:
                self.ftp = FTP(IP, timeout=TIMEOUT)
            except KeyboardInterrupt:
                self.error = '\n [-]Aborted'
                return
            except:
                if self.verbose:
                    print '\n [-]Error connecting to [%s]' % IP
                continue
            self.chkbanner = self.ftp.getwelcome()
            if re.search(self.banner, self.chkbanner):
                self.matchlist.append(IP)

def Help():
    usage ='''
    #######################################
    #                                     #
    #  Name: ftpcheck.py                  #
    #  Author: s3my0n                     #
    #  Email: RuSh4ck3R[at]gmail[dot]com  #
    #                                     #
    #######################################

    Usage: ftpcheck.py [list of ftp servers] [banner]

    Examples: ftpcheck.py -i chkme.txt -b "FTPU Ready"
              ftpcheck.py -v -i ftplist.txt -b "Microsoft FTP"
              ftpcheck.py -t 2 -i ips.txt -b "FTP"

    [Options]

        -v: Verbose mode
        -t: Timeout on each connection in seconds (default 3)
        -b: Banner to look for
        -i: Input FTP servers list

    If you want to save the results in a file use ' > <filename>'
    after the command arguments.

    Example: ftpcheck.py -i servers.txt -b "FTPU" > servers_result.txt

    I strongly recommend not using the verbose flag for this method.'''
    return usage

def Main(FILE, BANNER):
    try:
        temp = open(FILE)
        servers = temp.readlines()
        temp.close()
    except IOError:
        print '\n[-]Server list [%s] could not be retrieved: exiting' % (FILE)
        sys.exit()
    verbose = False
    if '-v' in sys.argv:
        verbose = True
    timeout = 3
    if '-t' in sys.argv[1:]:
        try:
            timeout = int(sys.argv[args.index('-t')+2].strip())
        except TypeError:
            print '\n[-]Timeout value must be a number'
    banner = BANNER

    chk = FtpCheck(servers, verbose, banner)
    
    if verbose:
        print '\n[+]Working...'
    chk.Check(timeout)
    if chk.matchlist != []:
        if verbose:
            print '\n[+]Found [%d] matches:\n' % (len(chk.matchlist))
        for s in chk.matchlist:
            print s
    else:
        if VERBOSE:
            print '\n[-]No match'
        else:
            print 'None'

if __name__ == '__main__':

    if len(sys.argv) not in [4, 5, 6, 7, 8]:
        print Help()
        sys.exit()

    args = sys.argv[1:]

    try:
        servers = sys.argv[args.index('-i')+2].strip()
        banner = sys.argv[args.index('-b')+2].strip()
    except ValueError:
        print Help()
        sys.exit()

    Main(servers, banner)
