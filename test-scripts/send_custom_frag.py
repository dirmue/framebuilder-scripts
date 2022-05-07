#!/usr/bin/env python3

'''Send an oversized IPv4 packet'''

import os
import sys
from framebuilder import udp, ipv4, tools


if len(sys.argv) < 3:
    print('Argument missing. Usage: ' + sys.argv[0] + \
            ' <interface> <remote IP> [remote port]')
    sys.exit(1)

if os.geteuid() != 0:
    print('You need to be root.')
    sys.exit(1)

if not tools.is_valid_ipv4_address(sys.argv[2]):
    print('Invalid remote IP address')
    sys.exit(1)

dst_ip = sys.argv[2]
ip_handler = ipv4.IPv4Handler(
        sys.argv[1], sys.argv[2],
        tools.get_if_ipv4_addr(sys.argv[1]),
        proto=17)
udp_dgram = udp.UDPDatagram()
udp_dgram.src_port = 44444
if len(sys.argv) < 4:
    udp_dgram.dst_port = 80
else:
    udp_dgram.dst_port = int(sys.argv[3])
udp_dgram.syn = 1
udp_dgram.payload = b'\xaa' * 5000
udp_dgram.info()
ip_handler.send(udp_dgram)
