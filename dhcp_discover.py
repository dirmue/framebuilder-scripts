#!/usr/bin/env python3

from framebuilder import tools, eth, ipv4, udp
import sys

socket = tools.create_socket(sys.argv[1])

frame = eth.Frame()
frame.dst_addr = 'ff:ff:ff:ff:ff:ff'
frame.src_addr = tools.get_mac_addr(sys.argv[1])
frame.ether_type = 0x0800

packet = ipv4.IPv4Packet()
packet.src_addr = '0.0.0.0'
packet.dst_addr = '255.255.255.255'
packet.ttl = 64
packet.protocol = 17
packet.flags = 2

dgram = udp.UDPDatagram()
dgram.src_port = 68
dgram.dst_port = 67

dhcp_discover = 0x01.to_bytes(1, 'big')               # OP
dhcp_discover += 0x01.to_bytes(1, 'big')              # HTYPE
dhcp_discover += 0x06.to_bytes(1, 'big')              # HLEN
dhcp_discover += 0x00.to_bytes(1, 'big')              # HOPS
dhcp_discover += 0x1234abcd.to_bytes(4, 'big')        # XID
dhcp_discover += 0x0.to_bytes(4, 'big')               # SECS + FLAGS
dhcp_discover += 0x0.to_bytes(16, 'big')              # IP ADDRESSES
dhcp_discover += bytes.fromhex(frame.src_addr.replace(':', ''))
dhcp_discover += 0x0.to_bytes(10, 'big')              # HW ADDR PADDING
dhcp_discover += 0x0.to_bytes(192, 'big')             # SNAME + FILE
dhcp_discover += 0x63825363.to_bytes(4, 'big')        # MAGIC DHCP COOKIE
dhcp_discover += 0x350101.to_bytes(3, 'big')          # DISCOVER
#dhcp_discover += 0x3204c0a80164.to_bytes(6, 'big')
dhcp_discover += 0x370401030f06.to_bytes(6, 'big')
dhcp_discover += 0xff.to_bytes(1, 'big')              # END MARK

dgram.payload = dhcp_discover
dgram.encapsulate(packet)
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
