#!/usr/bin/env python3

import os
import sys
import time
import socket
from framebuilder import ipv4, eth, tcp, tools, errors


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
        tools.print_rgb(f'> RESOLVED {sys.argv[1]}: {dst_ip}', (100, 100, 100))
    except:
        sys.exit(1)

try:
    dst_port = int(sys.argv[2])
except ValueError:
    print('Error: invalid remote port')

if_name = 'lo'
try:
    if_name = tools.get_route_if_name(dst_ip)
    tools.print_rgb(f'> INTERFACE: {if_name}', (100, 100, 100))
except errors.FailedMACQueryException:
    tools.print_rgb(f'{sys.argv[1]} not reachable', rgb=(200,0,0))
    sys.exit(1)

src_mac = tools.get_mac_addr(if_name)
tools.print_rgb(f'> LOCAL MAC: {src_mac}', (100, 100, 100))
src_ip = tools.get_if_ipv4_addr(if_name)
tools.print_rgb(f'> LOCAL IP: {src_ip}', (100, 100, 100))
src_port = tools.get_local_tcp_port()
tools.print_rgb(f'> LOCAL PORT: {src_port}', (100, 100, 100))
dst_mac = ''
try:
    dst_mac = tools.get_mac_for_dst_ip(dst_ip)
    tools.print_rgb(f'> REMOTE MAC: {dst_mac}', (100, 100, 100))
except errors.FailedMACQueryException:
    tools.print_rgb('Failed to obtain destination MAC address', rgb=(200,0,0))
    sys.exit(1)

pid = os.getpid()
tools.print_rgb(f'> IPv4 IDENTIFICATION: {pid & 0xffff}', (100, 100, 100))
sock = tools.create_socket(if_name)

frame = eth.Frame()
frame.src_addr = src_mac
frame.dst_addr = dst_mac
frame.ether_type = 0x0800

packet = ipv4.IPv4Packet()
packet.src_addr = src_ip
packet.dst_addr = dst_ip
packet.protocol = 6
packet.ttl = 64
packet.identification = pid & 0xffff

isn = tools.get_rfc793_isn()
tools.print_rgb(f'> INITIAL SEQUENCE NUMBER: {isn}', (100, 100, 100))

segment = tcp.TCPSegment()
segment.src_port = src_port
segment.dst_port = dst_port
segment.seq_nr = isn
segment.window = 65535
segment.syn = 1
segment.add_tcp_mss_option(1400)

print(f'\nSaying "Hello World" from {src_ip}:{src_port} to {dst_ip}:{dst_port}\n')

try:
    # hide local port
    tools.hide_from_kernel(if_name, dst_ip, dst_port)
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
    tools.unhide_from_kernel(if_name, dst_ip, dst_port)
    print('Bye!')
