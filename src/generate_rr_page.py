#!/usr/bin/env python2

import io
import os
import sys

def write_rr_page_32(f, is_replay):
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
    if is_replay:
        # privileged untraced syscalls are not executed during replay.
        # Instead we just emulate success.
        bytes[2] = 0x31
        bytes[3] = 0xc0 # xor %eax,%eax
    f.write(bytes)

def write_rr_page_64(f, is_replay):
    # See Task::did_waitpid for an explanation of why we have to
    # modify R11 and RCX here.
    bytes = bytearray([
        0x90, 0x90, # padding
        # rr_page_untraced_syscall_ip:
        0x0f, 0x05, # syscall
        # rr_page_ip_in_untraced_syscall:
        0x4d, 0x31, 0xdb, 0x90, 0x90, 0x90, 0x90, # xor %r11,%r11
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
    if is_replay:
        # privileged untraced syscalls are not executed during replay.
        # Instead we just emulate success.
        bytes[2] = 0x31
        bytes[3] = 0xc0 # xor %eax,%eax
    f.write(bytes)

generators_for = {
    'rr_page_32': lambda stream: write_rr_page_32(stream, False),
    'rr_page_64': lambda stream: write_rr_page_64(stream, False),
    'rr_page_32_replay': lambda stream: write_rr_page_32(stream, True),
    'rr_page_64_replay': lambda stream: write_rr_page_64(stream, True),
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
