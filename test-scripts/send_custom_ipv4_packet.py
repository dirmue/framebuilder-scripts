#!/usr/bin/env python3

from framebuilder import tools, eth, ipv4

frame_data = {}

iface = input('Schnittstelle [lo]: ')
if iface == '':
    iface = 'lo'
socket = tools.create_socket(iface)

frame_data['src_addr'] = input('Quell-MAC-Adresse [auto]: ')
if frame_data['src_addr'] == '':
    frame_data['src_addr'] = tools.get_mac_addr(iface)

frame_data['dst_addr'] = input('Ziel-MAC-Adresse  [00:00:00:00:00:00]: ')
if frame_data['dst_addr'] == '':
    frame_data['dst_addr'] = '000000000000'

ether_type = input('Ether Type [0x0800]: ')
if ether_type == '':
    ether_type = '0x0800'
frame_data['ether_type'] = int(ether_type, 16)

addvlan = input('VLAN-Tag einfügen? [j/N]: ')
if addvlan == 'j' or addvlan == 'J':
    vlan_id = input('VLAN-ID [1]: ')
    if vlan_id == '':
        vlan_id = '1'
    vlan_prio = input('VLAN-Priority [0]: ')
    if vlan_prio == '':
        vlan_prio = '0'
    vlan_dei = input('DEI (Drop Eligible Indicator) [0]: ')
    if vlan_dei == '' or vlan_dei != '1':
        vlan_dei = '0'
    vlan_tag = {'vlan_id': int(vlan_id), 
                'vlan_pcp': int(vlan_prio), 
                'vlan_dei': int(vlan_dei)}
    frame_data['vlan_tag'] = vlan_tag

frame = eth.Frame(frame_data)

packet = ipv4.IPv4Packet()

src_ip = input('Quell-IP-Adresse [auto]: ')
if src_ip == '':
    src_ip = tools.get_if_ipv4_addr(iface)
packet.src_addr = src_ip

dst_ip = input('Ziel-IP-Adresse [10.0.0.2]: ')
if dst_ip == '':
    dst_ip = '10.0.0.2'
packet.dst_addr = dst_ip

identification = input('Identification [0]: ')
if identification == '':
    identification = 0
packet.identification = int(identification)

flags = input('Flags [0]: ')
if flags == '':
    flags = 0
packet.flags = int(flags)

frag_offset = input('Fragment offset [0]: ')
if frag_offset == '':
    frag_offset = 0
packet.frag_offset = int(frag_offset)

ttl = input('Time-to-live [128]: ')
if ttl == '':
    ttl = 128
packet.ttl = int(ttl)

protocol = input('Protocol number [6]: ')
if protocol == '':
    protocol = 6
packet.protocol = int(protocol)

msg = input('Nachricht: ')
packet.payload = msg.encode()

packet.encapsulate(frame)
frame.info()
packet.info()

again = 'j'
while again == 'J' or again == 'j' or again == '':
    frame.send(socket)
    again = input('Noch einmal senden? [J/n]: ')
