#!/usr/bin/env python3

import os
import sys
import time
import socket
from framebuilder import ipv4, eth, tcp, tools


def encapsulate_and_send(socket, frame, packet, segment):
    '''
    Encapsulate data and send it via socket
    '''
    segment.encapsulate(packet)
    packet.encapsulate(frame)
    frame.send(sock)


if len(sys.argv) < 3:
    print('Argument missing. Usage: ' + sys.argv[0] + \
            ' <IPv4 address or hostname> <remote port>')
    sys.exit(1)

if (os.geteuid() != 0):
    print('You need to be root.')
    sys.exit(1)

dst_ip = sys.argv[1]

if not tools.is_valid_ipv4_address(sys.argv[1]):
    try:
        dst_ip = socket.gethostbyname(sys.argv[1])
    except:
        sys.exit(1)

try:
    dst_port = int(sys.argv[2])
except ValueError:
    print('Error: invalid remote port')

# obtain routing information
rt_info = tools.get_route(dst_ip)
# get neighbor cache
n_cache = tools.get_neigh_cache()

# set source MAC and IP address
src_mac = tools.get_mac_addr(rt_info['dev'])
src_ip = rt_info['prefsrc']
src_port = 12345

# set destination MAC address
dst_mac = "00:00:00:00:00:00"

# check if there is a gateway and query neighbor cache for MAC address
if rt_info.get("gateway", None) is not None:
    for n_entry in n_cache:
        if n_entry['dst'] == rt_info['gateway']:
            dst_mac = n_entry['lladdr']
            break
# if not query destination IP address
else:
    for n_entry in n_cache:
        if n_entry['dst'] == dst_ip:
            dst_mac = n_entry['lladdr']
            break

pid = os.getpid()
sock = tools.create_socket(rt_info['dev'])

print('\nSaying "Hello World" from {}:{} to {}:{}\n'.format(src_ip, src_port,
                                                            dst_ip, dst_port))

frame = eth.Frame()
frame.src_addr = src_mac
frame.dst_addr = dst_mac
frame.ether_type = 0x0800

packet = ipv4.IPv4Packet()
packet.src_addr = src_ip
packet.dst_addr = dst_ip
packet.protocol = 6
packet.ttl = 64
packet.identification = pid

# initial sequence number
isn = tools.get_rfc793_isn()

segment = tcp.TCPSegment()
segment.src_port = src_port
segment.dst_port = dst_port
segment.seq_nr = isn
segment.window = 65535
segment.syn = 1
segment.add_tcp_mss_option(1400)

try:
    # hide local port
    tools.hide_from_kernel(rt_info['dev'], dst_ip, dst_port)
    # send SYN
    encapsulate_and_send(sock, frame, packet, segment)
    tools.print_rgb('> SYN SENT', (0, 200, 0))
    while True:
        # wait for SYN-ACK --> SYN-SENT
        reply_data = sock.recv(65536)
        r_frame = eth.Frame.from_bytes(reply_data)
        if r_frame.ether_type != 0x0800:
            continue
        r_packet = ipv4.IPv4Packet.from_frame(r_frame)
        if r_packet.protocol != 6:
            continue
        r_segment = tcp.TCPSegment.from_packet(r_packet)
        if r_segment.src_port != segment.dst_port or \
           r_segment.syn != 1 or \
           r_segment.ack != 1 or \
           r_segment.ack_nr != segment.seq_nr + 1:
            continue
        tools.print_rgb('> SYN ACK RECEIVED', (0, 200, 0))

        # send ACK, complete handshake --> ESTABLISHED
        segment.delete_options()
        segment.syn = 0
        segment.ack = 1
        segment.seq_nr += 1
        segment.ack_nr = r_segment.seq_nr + 1
        encapsulate_and_send(sock, frame, packet, segment)
        tools.print_rgb('> ACK SENT', (0, 200, 0))
        break

    # send some data
    tools.print_rgb('> SENDING DATA', (50, 50, 255), True)
    segment.payload = 'Hello World\n'.encode()
    segment.psh = 1
    encapsulate_and_send(sock, frame, packet, segment)

    # now terminate the connection
    segment.seq_nr += len(segment.payload)
    segment.payload = b''
    segment.fin = 1
    segment.ack = 1
    segment.psh = 0
    encapsulate_and_send(sock, frame, packet, segment)
    tools.print_rgb('> FIN SENT', (0, 200, 0))

    while True:
        # wait for ACK --> FIN-WAIT-1
        reply_data = sock.recv(65536)
        r_frame = eth.Frame.from_bytes(reply_data)
        if r_frame.ether_type != 0x0800:
            continue
        r_packet = ipv4.IPv4Packet.from_frame(r_frame)
        if r_packet.protocol != 6:
            continue
        r_segment = tcp.TCPSegment.from_packet(r_packet)
        if r_segment.src_port != segment.dst_port or \
           r_segment.ack != 1 or \
           r_segment.ack_nr != segment.seq_nr + 1:
            continue
        tools.print_rgb('> FIN ACK RECEIVED', (0, 200, 0))
        break

    while True:
        # wait for FIN --> FIN-WAIT-2
        reply_data = sock.recv(65536)
        r_frame = eth.Frame.from_bytes(reply_data)
        if r_frame.ether_type != 0x0800:
            continue
        r_packet = ipv4.IPv4Packet.from_frame(r_frame)
        if r_packet.protocol != 6:
            continue
        r_segment = tcp.TCPSegment.from_packet(r_packet)
        if r_segment.src_port != segment.dst_port or \
           r_segment.ack != 1 or \
           r_segment.fin != 1 or \
           r_segment.ack_nr != segment.seq_nr + 1:
            continue
        tools.print_rgb('> FIN RECEIVED', (0, 200, 0))
        # final ACK
        segment.flags = 0
        segment.ack = 1
        segment.seq_nr += 1
        segment.ack_nr = r_segment.seq_nr + 1
        encapsulate_and_send(sock, frame, packet, segment)
        tools.print_rgb('> ACK SENT\n> CONNECTION CLOSED', (0, 200, 0))
        break

except KeyboardInterrupt:
    tools.print_rgb('\n--- Cancelled ---', (200, 0, 0), True)
finally:
    print('\nCleaning up...')
    sock.close()
    tools.unhide_from_kernel(rt_info['dev'], dst_ip, dst_port)
    print('Bye!')
