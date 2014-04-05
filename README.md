power-scanner
=============

Colman's Cyber Security course exercise 

Port scanner - powscan.py
=============


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


### Example 1 - full tcp scan:

    root@jossef-VirtualBox:/home/jossef/Desktop/workspace# python powscan.py -iface_ip 10.0.2.15 -target_ip 77.232.72.241 -interval 100 -timeout 1000 -ports 80-90 20 -scan_type full_tcp -banner
    scanning ... (please be patient)
    
    +---------------+------+------------------+-----------+------------------+--------+
    |     Target    | Port | Port Description | Scan Type | Operating System | Server |
    +---------------+------+------------------+-----------+------------------+--------+
    | 77.232.72.241 |  80  |       http       |  full_tcp |   apache 2.2.8   |        |
    +---------------+------+------------------+-----------+------------------+--------+

![image](https://cloud.githubusercontent.com/assets/1287098/2623831/26cc489a-bd0a-11e3-82b5-135eb75e5aa8.png)


### Example 2 - ack scan:

    root@jossef-VirtualBox:/home/jossef/Desktop/workspace# python powscan.py -iface_ip 10.0.2.15 -target_ip 77.232.72.241 -interval 100 -timeout 1000 -ports 80-90 20 -scan_type ack -banner
    scanning ... (please be patient)
    
    +---------------+------+-------------------------------------------------------+-----------+------------------+--------+
    |     Target    | Port |                    Port Description                   | Scan Type | Operating System | Server |
    +---------------+------+-------------------------------------------------------+-----------+------------------+--------+
    | 77.232.72.241 |  80  |                          http                         |    ack    |                  |        |
    | 77.232.72.241 |  81  |                        unknown                        |    ack    |                  |        |
    | 77.232.72.241 |  82  |                        unknown                        |    ack    |                  |        |
    | 77.232.72.241 |  83  |                        unknown                        |    ack    |                  |        |
    | 77.232.72.241 |  84  |                        unknown                        |    ack    |                  |        |
    | 77.232.72.241 |  85  |                        unknown                        |    ack    |                  |        |
    | 77.232.72.241 |  86  |                        unknown                        |    ack    |                  |        |
    | 77.232.72.241 |  87  |                        unknown                        |    ack    |                  |        |
    | 77.232.72.241 |  88  |                        kerberos                       |    ack    |                  |        |
    | 77.232.72.241 |  89  |                        unknown                        |    ack    |                  |        |
    | 77.232.72.241 |  90  | dnsix (dod network security for information exchange) |    ack    |                  |        |
    | 77.232.72.241 |  20  |                   ftp data transfer                   |    ack    |                  |        |
    +---------------+------+-------------------------------------------------------+-----------+------------------+--------+

![image](https://cloud.githubusercontent.com/assets/1287098/2623832/4deefbde-bd0a-11e3-94f5-fc0af7208cdf.png)


### Example 3 - udp scan:

    root@jossef-VirtualBox:/home/jossef/Desktop/workspace# python powscan.py -iface_ip 10.0.2.15 -target_ip 77.232.72.241 -interval 100 -timeout 1000 -ports 80-90 20 -scan_type udp -banner
    scanning ... (please be patient)
    
    +---------------+------+-------------------------------------------------------+-----------+------------------+--------+
    |     Target    | Port |                    Port Description                   | Scan Type | Operating System | Server |
    +---------------+------+-------------------------------------------------------+-----------+------------------+--------+
    | 77.232.72.241 |  80  |                          http                         |    udp    |   apache 2.2.8   |        |
    | 77.232.72.241 |  81  |                        unknown                        |    udp    |                  |        |
    | 77.232.72.241 |  82  |                        unknown                        |    udp    |                  |        |
    | 77.232.72.241 |  83  |                        unknown                        |    udp    |                  |        |
    | 77.232.72.241 |  84  |                        unknown                        |    udp    |                  |        |
    | 77.232.72.241 |  85  |                        unknown                        |    udp    |                  |        |
    | 77.232.72.241 |  86  |                        unknown                        |    udp    |                  |        |
    | 77.232.72.241 |  87  |                        unknown                        |    udp    |                  |        |
    | 77.232.72.241 |  88  |                        kerberos                       |    udp    |                  |        |
    | 77.232.72.241 |  89  |                        unknown                        |    udp    |                  |        |
    | 77.232.72.241 |  90  | dnsix (dod network security for information exchange) |    udp    |                  |        |
    | 77.232.72.241 |  20  |                   ftp data transfer                   |    udp    |                  |        |
    +---------------+------+-------------------------------------------------------+-----------+------------------+--------+


### Example 4 - stealth scan:
    
    root@jossef-VirtualBox:/home/jossef/Desktop/workspace# python powscan.py -iface_ip 10.0.2.15 -target_ip 77.232.72.241 -interval 100 -timeout 1000 -ports 80-90 20 -scan_type stealth -banner
    scanning ... (please be patient)
    
    +---------------+------+------------------+-----------+------------------+--------+
    |     Target    | Port | Port Description | Scan Type | Operating System | Server |
    +---------------+------+------------------+-----------+------------------+--------+
    | 77.232.72.241 |  80  |       http       |  stealth  |   apache 2.2.8   |        |
    +---------------+------+------------------+-----------+------------------+--------+


![image](https://cloud.githubusercontent.com/assets/1287098/2623812/2d03d1b6-bd09-11e3-8756-b39c14a67432.png)


### Example 5 - fin scan:

    root@jossef-VirtualBox:/home/jossef/Desktop/workspace# python powscan.py -iface_ip 10.0.2.15 -target_ip 77.232.72.241 -interval 100 -timeout 1000 -ports 80-90 20 -scan_type fin -banner
    scanning ... (please be patient)
    
    +--------+------+------------------+-----------+------------------+--------+
    | Target | Port | Port Description | Scan Type | Operating System | Server |
    +--------+------+------------------+-----------+------------------+--------+
    +--------+------+------------------+-----------+------------------+--------+
    


![image](https://cloud.githubusercontent.com/assets/1287098/2623822/c0eb1790-bd09-11e3-8577-b0377c952b1b.png)

    
Network mapper - powmap.py
=============

    usage: powmap.py [-h] -iface_ip IP -timeout TIME
    
    Powmap - Cyber security cource TASK 2 Building Scanning tool
    
    optional arguments:
      -h, --help     show this help message and exit
      -iface_ip IP   network ip
      -timeout TIME  timeout on socket connections (milliseconds)


