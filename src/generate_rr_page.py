#!/usr/bin/env python2

import io
import os
import sys

def write_rr_page_32(f):
    bytes = bytearray([
        0x90, 0x90, # padding
        # rr_page_untraced_syscall_ip:
        0xcd, 0x80, # int 0x80
        # rr_page_ip_in_untraced_syscall:
        0xc3, # ret
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, # padding
        # rr_page_traced_syscall_ip:
        0xcd, 0x80, # int 0x80
        # rr_page_ip_in_traced_syscall:
        0xc3, # ret
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    ])
    f.write(bytes)
    f.write(bytes)

def write_rr_page_64(f):
    # See Task::did_waitpid for an explanation of why we have to
    # modify R11 and RCX here.
    bytes = bytearray([
        0x90, 0x90, # padding
        # rr_page_untraced_syscall_ip:
        0x0f, 0x05, # syscall
        # rr_page_ip_in_untraced_syscall:
        0x49, 0x81, 0xe3, 0xff, 0xfe, 0xff, 0xff, # and $0xfffffffffffffeff,%r11
        0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, # mov $-1,%rcx
        0xc3,             # ret
        0x90, 0x90, 0x90, # padding
        # rr_page_traced_syscall_ip:
        0x0f, 0x05, # syscall
        # rr_page_ip_in_traced_syscall:
        0xc3, # ret
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    ])
    f.write(bytes)
    f.write(bytes)

generators_for = {
    'rr_page_32': write_rr_page_32,
    'rr_page_64': write_rr_page_64,
}

def main(argv):
    filename = argv[0]
    base = os.path.basename(filename)

    if os.access(filename, os.F_OK):
        with open(filename, 'r') as f:
            before = f.read()
    else:
        before = ""

    stream = io.BytesIO()
    generators_for[base](stream)
    after = stream.getvalue()
    stream.close()

    if before != after:
        with open(filename, 'w') as f:
            f.write(after)

if __name__ == '__main__':
    main(sys.argv[1:])
