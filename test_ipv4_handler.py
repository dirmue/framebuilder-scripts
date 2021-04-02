#!/usr/bin/env python3

import sys
from itertools import cycle
import framebuilder.ipv4 as ip4
import framebuilder.icmpv4 as icmp
from framebuilder.tools import print_rgb, print_pkg_data_hex

ip4_handler = ip4.IPv4Handler(sys.argv[1], 1, block=0, t_out=5)

# send packet
icmp_msg = icmp.ICMPEchoRequest()
icmp_msg.identifier = 500
icmp_msg.data = 'Ping!'.encode()
icmp_msg.encapsulate(ip4_handler.nextpk_out)
ip4_handler.send()
print_rgb('packet sent', (50, 255, 50), True)
ip4_handler.nextpk_out.info()
print_pkg_data_hex(ip4_handler.frame.get_bytes(), 16)

# receive something
wait_cyc = 0
wait_str = cycle(['\\','|','/','-'])
try:
    while not ip4_handler.receive():
        if wait_cyc == 0:
            print_rgb('\r'+wait_str.__next__(), (100, 100, 255), end= '')
            wait_cyc = 1e5
        else:
            wait_cyc -=1
    print_rgb('\rpacket received', (50, 255, 50), True)
    ip4_handler.nextpk_in.info()
    print_pkg_data_hex(ip4_handler.frame.get_bytes(), 16)
except KeyboardInterrupt:
    print_rgb('\nBye', (255, 50, 50), True)
finally:
    del ip4_handler
