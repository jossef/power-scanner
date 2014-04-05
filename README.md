power-scanner
=============

Colman's Cyber Security course exercise 

run python powscan.py 

    -ip target ip address 
    - t time interval between each scan in milliseconds 
    -pt protocol type [UDP/TCP/ICMP] 
    -p ports [ can be range : -p 22-54 , can be single port : -p 80 , can be 
    combination : -p 80,43,23,125] 
    -type scan type [full,stealth,fin,ack] 
    -b bannerGrabber status (Should work only for TCP)
