#!/usr/bin/env python3

import cpktools as tools
import cpkether as eth

frame_data = {
        'header': {
            'src_addr': '30:e3:7a:a5:0a:af',
            'dst_addr': 'c8:d3:ff:d3:c3:d5',
            'ether_type': 0x0800,
            'vlan_tag': None
        },
        'payload': 'Testframe'.encode()
}

socket = tools.create_socket('wlp3s0')
frame = eth.Frame(frame_data)
print('-------- OLD FRAME --------')
print(frame.get_dict())
tools.print_pkg_data_hex(frame.get_bytes())
print(frame)

new_frame = eth.Frame.from_bytes(frame.get_bytes())
print('-------- NEW FRAME --------')
print(new_frame.get_dict())
tools.print_pkg_data_hex(new_frame.get_bytes())
print(new_frame)

again = 'j'
while again == 'J' or again == 'j' or again == '':
    new_frame.send(socket)
    again = input('Noch einmal senden? [J/n]: ')
