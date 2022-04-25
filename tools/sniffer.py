#!/usr/bin/env python3

import sys
import os
from framebuilder import eth as ether, ipv4, icmpv4, udp, tcp, tools, defs


def frame_filter(frame, field_name, field_value):
    d = frame.eth_hdr.get_dict()
    if field_name.starts_with('vlan'):
        d = d['vlan_tag']
    return d[field_name] == field_value


def visualize(frame):
    print('EthernetHeader: SRC={} DST={} UPPER_LAYER={}'.format(
          frame.src_addr,
          frame.dst_addr,
          defs.get_protocol_str(frame.ether_type)))
    layer3_formatter.get(frame.ether_type, dummy_formatter)(frame)
    if len(sys.argv) > 2:
        if sys.argv[2] == 'ascii':
            tools.print_pkg_data_ascii(frame.get_bytes())
        if sys.argv[2] == 'hex':
            tools.print_pkg_data_hex(frame.get_bytes())

def tcp_formatter(ip_packet):
    proto_packet = tcp.TCPSegment.from_bytes(ip_packet.payload)
    print('    TCP Header: SRC={} DST={} LEN={} CKS=0x{:04x}'.format(
        proto_packet.src_port,
        proto_packet.dst_port,
        proto_packet.length,
        proto_packet.checksum
        ))

def udp_formatter(ip_packet):
    proto_packet = udp.UDPDatagram.from_bytes(ip_packet.payload)
    print('    UDP Header: SRC={} DST={} LEN={} CKS=0x{:04x}'.format(
        proto_packet.src_port,
        proto_packet.dst_port,
        proto_packet.length,
        proto_packet.checksum
        ))

def icmpv4_formatter(ip_packet):
    icmp_msg = icmpv4.ICMPv4Message.from_ipv4_packet(ip_packet)
    print('   ICMPv4 Header: CODE={} TYPE={}'.format(icmp_msg.icmp_code,
                                                     icmp_msg.icmp_type)) 

def ipv4_formatter(frame):
    ip_packet = ipv4.IPv4Packet.from_bytes(frame.payload)
    print('  IPHeader: SRC={} DST={} PROTO={} TTL={} LEN={}'.format(
        ip_packet.src_addr,
        ip_packet.dst_addr,
        defs.get_iana_protocol_str(ip_packet.protocol),
        ip_packet.ttl,
        ip_packet.total_length
        ))
    layer4_formatter.get(ip_packet.protocol, dummy_formatter)(ip_packet)

def arp_formatter(frame):
    arp_msg = ether.ArpMessage.from_frame(frame)
    print('    ARPHeader: SND_MAC={} SND_IP={} TGT_MAC={} TGT_IP={} OP={}'\
          .format(arp_msg.snd_hw_addr, arp_msg.snd_ip_addr,
                  arp_msg.tgt_hw_addr, arp_msg.tgt_ip_addr,
                  arp_msg.operation))

def dummy_formatter(anything):
    pass

layer4_formatter = {1:  icmpv4_formatter,
                    6:  tcp_formatter,
                    17: udp_formatter}

layer3_formatter = {0x0800: ipv4_formatter,
                    0x0806: arp_formatter}

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Argument missing. Usage: ' + sys.argv[0] + \
                ' <interface> [ascii|hex]')
        sys.exit(1)

    if (os.geteuid() != 0):
        print('You need to be root.')
        sys.exit(1)

    #
    # In order not to see any oversized frames, turn off all offloading
    #
    os.system('ethtool -K {} tx off rx off gro off gso off &>/dev/null'.format(sys.argv[1]))

    s = tools.create_socket(sys.argv[1])

    try:
        while True:
            data, addr = s.recvfrom(9022)
            frame = ether.Frame.from_bytes(data)

            # only allow following packets
            # filter_cond = [True] --> Show all
            # filter_cond = [frame.ether_type == 0x0806] --> ARP only
            # filter_cond = [frame.ether_type == 0x0800] --> IPv4 only
            filter_cond = [True]
            
            if not any(filter_cond):
                continue

            visualize(frame)

    except KeyboardInterrupt:
        print('\nBye!')
    finally:
        s.close()
        # Turn offloading on again
        os.system('ethtool -K {} tx on rx on gro on gso on &>/dev/null'.format(sys.argv[1]))
