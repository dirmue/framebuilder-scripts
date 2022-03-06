#!/usr/bin/env python3

import os
import sys
import random
from framebuilder import tcp, ipv4, eth, tools, errors


if len(sys.argv) < 2:
    print('Argument missing. Usage: ' + sys.argv[0] + \
            ' <remote IP>')
    sys.exit(1)

if (os.geteuid() != 0):
    print('You need to be root.')
    sys.exit(1)

if not tools.is_valid_ipv4_address(sys.argv[1]):
    raise errors.InvalidIPv4AddrException(sys.argv[1])

dst_ip = sys.argv[1]
ip_handler = ipv4.IPv4Handler('lo', dst_ip, '8.8.8.8')
tcp_segment = tcp.TCPSegment()
tcp_segment.src_port = 33333
tcp_segment.dst_port = 80
tcp_segment.syn = 1
tcp_segment.payload = random.randbytes(5000)
ip_handler.send(tcp_segment)
