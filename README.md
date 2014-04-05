power-scanner
=============

Colman's Cyber Security course exercise 

run python powscan.py 

    usage: powscan.py [-h] -iface_ip IP -target_ip IP -interval TIME -timeout TIME
                      -ports PORT [PORT ...] -scan_type TYPE [-banner]
    
    Powscan - Cyber security cource TASK 2 Building Scanning tool
    
    optional arguments:
      -h, --help            show this help message and exit
      -iface_ip IP          sending interface ip address (v4 only)
      -target_ip IP         target ip address (v4 only)
      -interval TIME        time interval between each scan (milliseconds)
      -timeout TIME         timeout on socket connections (milliseconds)
      -ports PORT [PORT ...]
                            ports can be range : -p 22-54 can be single port : -p
                            80 can be combination (space separated) : -p 80 43 23
                            125]
      -scan_type TYPE       scan type [full,stealth,fin,ack]
      -banner               if you would like to grab that banner status (Should work only for TCP)






