#!/usr/bin/env python3

import sys
from random import randrange
from framebuilder import tools, eth

if len(sys.argv) < 2:
    print('Missing arguments')
    print(f'Usage: {sys.argv[0]} interface')
    sys.exit(1)


if_name = sys.argv[1]
socket = tools.create_socket(if_name)
frame = eth.Frame()
frame.dst_addr = '02:00:00:00:00:00' 
frame.ether_type = 0x0800
try:
    while True:
        src_mac = f'{format(randrange(256), "02x")}'
        for p in range(5):
            src_mac += f':{format(randrange(256), "02x")}'
        frame.src_addr = src_mac
        frame.send(socket)
        count += 1
        info = f'src={src_mac}'
        tools.print_rgb(info, rgb=(200, 200, 200), bold=True)
except KeyboardInterrupt:
    tools.print_rgb('\nstopped; Goodbye!', rgb=(0, 200, 0), bold=True)
    socket.close()
