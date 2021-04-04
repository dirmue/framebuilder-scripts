#!/usr/bin/env python3

from framebuilder import ipv4, tools

ip_handler = ipv4.IPv4Handler('127.0.0.1')

try:
    while True:
        pk = ip_handler.receive()
        if pk is not None:
            tools.print_pkg_data_hex(pk.get_bytes())
            pk.info()
            break
except KeyboardInterrupt:
    tools.print_rgb('\n--- Cancelled ---', (200, 0, 0), True)
finally:
    print('\nCleaning up...')
    del ip_handler
    print('Bye!')
