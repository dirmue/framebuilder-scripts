#!/usr/bin/env python3

import cpktools as tools
import cpkether as eth
import cpkipv4 as ip4
import cpkudp as udp

socket = tools.create_socket('wlp3s0')

packet = ip4.IPv4Packet()
packet.src_addr = '192.168.2.106'
packet.dst_addr = '78.47.151.229'
packet.ttl = 64
packet.protocol = 17
packet.flags = 2

dgram = udp.UDPDatagram()
dgram.src_port = 12345
dgram.dst_port = 23456
dgram.payload = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO'.encode()
dgram.encapsulate(packet)

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
    dgram.info()
    tools.print_pkg_data_hex(frame.get_bytes())
    again = input('Noch einmal senden? [J/n]: ')
    packet.ttl += 1
