#!/usr/bin/env python3

import os
import sys
import time
import socket
from framebuilder import tools, eth, ipv4, icmpv4

if len(sys.argv) < 2:
    print('Argument missing. Usage: ' + sys.argv[0] + \
            ' <IPv4 address>')
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

# obtain routing information
rt_info = tools.get_route(dst_ip)
# get neighbor cache
n_cache = tools.get_neigh_cache()

# set source MAC and IP address
src_mac = tools.get_mac_addr(rt_info['dev'])
src_ip = rt_info['prefsrc']

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
sock = tools.create_socket(rt_info['dev'], blocking=0)

frame = eth.Frame()
frame.src_addr = src_mac
frame.dst_addr = dst_mac
frame.ether_type = 0x0800

packet = ipv4.IPv4Packet()
packet.src_addr = src_ip
packet.dst_addr = dst_ip
packet.protocol = 1
packet.ttl = 64
packet.identification = pid

# generate payload
pl_length = 56
payload = b''
for num in range(pl_length):
    payload += tools.to_bytes(num & 0xff, 1)


echo_req = icmpv4.ICMPEchoRequest()
echo_req.identifier = pid
echo_req.sequence_number = 1
echo_req.data = payload

# encapsulate data
echo_req.encapsulate(packet)
packet.encapsulate(frame)

# counters and initial time for statistics
pk_sent = 0
pk_recv = 0
t_init = time.time_ns()

tools.hide_from_kernel(rt_info['dev'], dst_ip, 0, 'icmp')

print("PING {} ({}) {}({}) bytes of data".format(sys.argv[1], dst_ip, pl_length,
                                            len(frame.payload)))
try:
    while True:
        # initialize timers
        t_start = time.time_ns()
        t_out = 1.0
        t_diff = 0.0

        r_echo_reply = None
        waiting_for_answer = True

        frame.send(sock)
        pk_sent += 1

        while waiting_for_answer and t_diff < t_out:
            try:
                frame_bytes = sock.recv(65535)
                
                r_frame = eth.Frame.from_bytes(frame_bytes)

                # Skip if not IPv4
                if r_frame.ether_type != 0x0800:
                    continue
                r_packet = ipv4.IPv4Packet.from_frame(r_frame)
                
                # Skip if not an ICMP message
                if r_packet.protocol != 1:
                    continue

                r_echo_reply = icmpv4.ICMPv4Message.from_ipv4_packet(r_packet)
                
                # Check if ICMP message is an echo reply with our pid and
                # sequence number
                if isinstance(r_echo_reply, icmpv4.ICMPEchoReply) and \
                   r_echo_reply.identifier == pid and \
                   r_echo_reply.sequence_number == echo_req.sequence_number:
                    
                    pk_recv += 1

                    t_reply = (time.time_ns() - t_start) / 1e6
                    print("{} Bytes from {}: icmp_seq={} ttl={} time={:.1f} ms"\
                          .format(len(r_echo_reply.get_bytes()), 
                                  r_packet.src_addr,
                                  r_echo_reply.sequence_number,
                                  r_packet.ttl,
                                  t_reply))
                    # update sequence number...      
                    echo_req.sequence_number += 1
                    # ...and encapsulate data again
                    echo_req.encapsulate(packet)
                    packet.encapsulate(frame)

                    waiting_for_answer = False
            except:
                pass
            # Calculate passed time in seconds
            t_diff = (time.time_ns() - t_start) / 1e9

        if t_diff < t_out:
            time.sleep(t_out - t_diff)
except KeyboardInterrupt:
    print("\n--- {} ping statistics ---".format(sys.argv[1]))
    print("{} packets sent, {} packets received, {}% packet loss, time {}ms"\
          .format(pk_sent, pk_recv, int((1 - (pk_recv / pk_sent)) * 100),
                  int((time.time_ns() - t_init) / 1e6)))
    tools.unhide_from_kernel(rt_info['dev'], dst_ip, 0, 'icmp', 0.2)
    sock.close()
