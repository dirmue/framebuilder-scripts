#!/usr/bin/env python3

import os
import sys
import time
import socket
from framebuilder import ipv4, eth, tcp, tools


def encapsulate_and_send(socket, frame, packet, segment):
    '''
    Encapsulate data and send it via socket
    '''
    segment.encapsulate(packet)
    packet.encapsulate(frame)
    frame.send(sock)


if len(sys.argv) < 2:
    print('Argument missing. Usage: ' + sys.argv[0] + \
            ' <remote port>')
    sys.exit(1)

if (os.geteuid() != 0):
    print('You need to be root.')
    sys.exit(1)

try:
    dst_port = int(sys.argv[1])
except ValueError:
    print('Error: invalid remote port')

iface = 'lo'
ip_handler = ipv4.IPv4Handler('127.0.0.1', 1)

try:
    # hide local port
    tools.hide_from_kernel(iface, '127.0.0.1', dst_port, proto='icmp')
    while True:
        if ip_handler.receive():
            tools.print_pkg_data_hex(ip_handler.nextpk_in.get_bytes())
            ip_handler.nextpk_in.info()
            break

except KeyboardInterrupt:
    tools.print_rgb('\n--- Cancelled ---', (200, 0, 0), True)
finally:
    print('\nCleaning up...')
    tools.unhide_from_kernel(iface, '127.0.0.1', dst_port, proto='icmp')
    del ip_handler
    print('Bye!')
