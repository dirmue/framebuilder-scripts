#!/usr/bin/env python3

from framebuilder import tools, eth, ipv4, tcp

socket = tools.create_socket('enp7s0f3u1u1')

packet = ipv4.IPv4Packet()
packet.src_addr = '10.20.32.10'
packet.dst_addr = '78.47.151.229'
packet.ttl = 64
packet.protocol = 6
packet.identification = 123
packet.flags=2

segment = tcp.TCPSegment()
segment.src_port = 45678
segment.dst_port = 5555
segment.seq_nr = 123456
segment.window = 64240
segment.syn = 1
segment.add_tcp_mss_option(1500)
segment.encapsulate(packet)

frame = eth.Frame()
frame.src_addr = '48:2a:e3:9d:3b:c7'
frame.dst_addr = '6c:b3:11:08:36:28'
frame.ether_type = 0x0800

again = 'j'
while again == 'J' or again == 'j' or again == '':
    frame.payload = packet.get_bytes()
    frame.send(socket)
    frame.info()
    packet.info()
    segment.info()
    tools.print_pkg_data_hex(frame.get_bytes())
    again = input('Noch einmal senden? [J/n]: ')
    packet.ttl += 1
