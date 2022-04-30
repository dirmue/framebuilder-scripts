#!/usr/bin/env python3

from framebuilder import tools, eth

frame_data = {}

iface = input('Schnittstelle [lo]: ')
if iface == '':
    iface = 'lo'
socket = tools.create_socket(iface)

frame_data['src_addr'] = input('Quell-MAC_Adresse [00:00:00:00:00:00]: ')
if frame_data['src_addr'] == '':
    frame_data['src_addr'] = '000000000000'

frame_data['dst_addr'] = input('Ziel-MAC_Adresse  [00:00:00:00:00:00]: ')
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

msg = input('Nachricht: ')
frame_data['payload'] = msg.encode()

frame = eth.Frame(frame_data)
frame.info()

again = 'j'
while again == 'J' or again == 'j' or again == '':
    frame.send(socket)
    again = input('Noch einmal senden? [J/n]: ')
