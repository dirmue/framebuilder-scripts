#!/usr/bin/env python3
'''Single Reverse ARP query script'''

import sys
from framebuilder import eth, tools, errors

def print_rarp_info(rarp_msg :eth.ArpMessage):
    print(f'sender hardware address: {rarp_msg.snd_hw_addr}')
    print(f'sender ip address: {rarp_msg.snd_ip_addr}')
    print(f'target hardware address: {rarp_msg.tgt_hw_addr}')
    print(f'target ip address: {rarp_msg.tgt_ip_addr}')
    print('hex dump:')
    tools.print_pkg_data_hex(rarp_msg.get_bytes(), 16)

if len(sys.argv) < 2:
    print(f'USAGE: {sys.argv[0]} <interface>')
    sys.exit(1)

iface = sys.argv[1]
try:
    socket = eth.create_socket(iface)
except (errors.SocketBindException, errors.SocketCreationException):
    print(f'Socket creation failed. Are you root and does {iface} exist?')
    sys.exit(2)

local_mac = tools.get_mac_addr(iface)

rarp_req = eth.ArpMessage({
        'operation': 3,
        'src_addr': local_mac,
        'dst_addr': 'ff:ff:ff:ff:ff:ff',
        'snd_hw_addr': local_mac,
        'snd_ip_addr': '0.0.0.0',
        'tgt_hw_addr': local_mac,
        'tgt_ip_addr': '0.0.0.0'
    })
rarp_req.ether_type = 0x8035 # Reverse ARP has its own ethertype value
rarp_req.send(socket)
tools.print_rgb(f'RARP Request for {local_mac} sent:', (0,128,0))
print_rarp_info(rarp_req)
try:
    while True:
        frame = eth.Frame.from_bytes(socket.recv(1514))
        if frame.ether_type != 0x8035:
            continue
        rarp_reply = eth.ArpMessage.from_frame(frame)
        if rarp_reply.operation == 4 and rarp_reply.tgt_hw_addr == local_mac:
            tools.print_rgb(f'\nRARP Reply for {local_mac} received:', (0,128,0))
            print_rarp_info(rarp_reply)
            tools.print_rgb(f'\n{local_mac} has {rarp_reply.tgt_ip_addr}',(128,96,0), True)
            break
except KeyboardInterrupt:
    print(f'\nCtrl-C ... QUITTING')
finally:
    socket.close()
