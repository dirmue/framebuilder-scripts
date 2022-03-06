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

if_name = tools.get_route_if_name(dst_ip)
ip_handler = ipv4.IPv4Handler(if_name, dst_ip, proto=1, block=0)
pid = os.getpid()

## build ICMPv4 message
# generate payload
pl_length = 56
payload = b''
for num in range(pl_length):
    payload += tools.to_bytes(num & 0xff, 1)
echo_req = icmpv4.ICMPEchoRequest()
echo_req.identifier = pid
echo_req.sequence_number = 1
echo_req.data = payload

# counters and initial time for statistics
pk_sent = 0
pk_recv = 0
t_init = time.time_ns()

print(f'PING {sys.argv[1]} ({dst_ip}) {pl_length} bytes of data')
try:
    while True:
        # initialize timers
        t_start = time.time_ns()
        t_out = 1.0
        t_diff = 0.0

        r_echo_reply = None
        waiting_for_answer = True

        ip_handler.send(echo_req, dont_frag=True)
        pk_sent += 1

        while waiting_for_answer and t_diff < t_out:
            
            r_packet = ip_handler.receive()

            if r_packet is None:
                # Calculate passed time in seconds
                # t_diff = (time.time_ns() - t_start) / 1e9
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
                waiting_for_answer = False
                # Calculate passed time in seconds
                t_diff = (time.time_ns() - t_start) / 1e9

        if t_diff < t_out:
            time.sleep(t_out - t_diff)
except KeyboardInterrupt:
    print(f'\n--- {sys.argv[1]} ping statistics ---')
    print('{} packets sent, {} packets received, {}% packet loss, time {}ms'\
          .format(pk_sent, pk_recv, int((1 - (pk_recv / pk_sent)) * 100),
                  int((time.time_ns() - t_init) / 1e6)))
    del ip_handler
