#!/usr/bin/env python3

from framebuilder import tools, eth, ipv4 as ip4, icmpv4 as icmp

socket = tools.create_socket('wlo1')
frame = eth.Frame()
frame.src_addr = 'dc:41:a9:36:cf:f4'
frame.dst_addr = '54:25:ea:a5:00:f9'
frame.ether_type = 0x0800

packet = ip4.IPv4Packet()
packet.src_addr = '192.168.2.106'
packet.dst_addr = '78.47.151.229'
packet.protocol = 1
packet.flags = 2

#icmp_msg = icmp.ICMPParameterProblem({'pointer': 1})
icmp_msg = icmp.ICMPEchoRequest()
icmp_msg.data = "123456".encode()

icmp_msg.encapsulate(packet)
packet.encapsulate(frame)

again = 'j'
while again == 'J' or again == 'j' or again == '':
    frame.send(socket)
    frame.info()
    packet.info()
    icmp_msg.info()
    again = input('Noch einmal senden? [J/n]: ')
