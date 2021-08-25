#!/usr/bin/env python3

import cpktools as tools
import cpkether as eth
import cpkipv4 as ip4

socket = tools.create_socket('wlp3s0')

packet = ip4.IPv4Packet()
packet.src_addr = '10.0.0.1'
packet.dst_addr = '10.0.0.2'
packet.ttl = 1
packet.protocol = 253
packet.flags = 2
packet.payload = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO'.encode()

frame = eth.Frame()
frame.src_addr = 'dc:41:a9:36:cf:f4'
frame.dst_addr = '54:25:ea:a5:00:f9'
frame.ether_type = 0x0800

again = 'j'
while again == 'J' or again == 'j' or again == '':
    frame.payload = packet.get_bytes()
    frame.send(socket)
    frame.info()
    packet.info()
    again = input('Noch einmal senden? [J/n]: ')
    packet.ttl += 1
