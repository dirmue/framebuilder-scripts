#!/usr/bin/env python3
'''Single ARP query script'''

import sys
from framebuilder import eth, tools, errors

def print_arp_info(arp_msg :eth.ArpMessage):
    print(f'sender hardware address: {arp_msg.snd_hw_addr}')
    print(f'sender ip address: {arp_msg.snd_ip_addr}')
    print(f'target hardware address: {arp_msg.tgt_hw_addr}')
    print(f'target ip address: {arp_msg.tgt_ip_addr}')
    print('hex dump:')
    tools.print_pkg_data_hex(arp_msg.get_bytes(), 16)

if len(sys.argv) < 3:
    print(f'USAGE: {sys.argv[0]} <interface> <ip_address>')
    sys.exit(1)

iface = sys.argv[1]
try:
    socket = eth.create_socket(iface)
except (errors.SocketBindException, errors.SocketCreationException):
    print(f'Socket creation failed. Are you root and does {iface} exist?')
    sys.exit(2)

ipaddr = sys.argv[2]
if not tools.is_valid_ipv4_address(ipaddr):
    print(f'{ipaddr} is not a valid IPv4 address!')
    socket.close()
    sys.exit(3)

local_mac = tools.get_mac_addr(iface)
local_ip = tools.get_if_ipv4_addr(iface)

arp_req = eth.ArpMessage({
        'operation': 1,
        'src_addr': local_mac,
        'dst_addr': 'ff:ff:ff:ff:ff:ff',
        'snd_hw_addr': local_mac,
        'snd_ip_addr': local_ip,
        'tgt_hw_addr': '00:00:00:00:00:00',
        'tgt_ip_addr': ipaddr
    })

arp_req.send(socket)
tools.print_rgb(f'ARP Request for {ipaddr} sent:', (0,128,0))
print_arp_info(arp_req)
try:
    while True:
        frame = eth.Frame.from_bytes(socket.recv(1514))
        if frame.ether_type != 0x0806:
            continue
        arp_reply = eth.ArpMessage.from_frame(frame)
        if arp_reply.operation == 2 and arp_reply.snd_ip_addr == ipaddr:
            tools.print_rgb(f'\nARP Reply for {ipaddr} received:', (0,128,0))
            print_arp_info(arp_reply)
            tools.print_rgb(f'\n{ipaddr} is at {arp_reply.tgt_hw_addr}',(128,96,0), True)
            break
except KeyboardInterrupt:
    print(f'\nCtrl-C ... QUITTING')
finally:
    socket.close()
