#!/usr/bin/env python2

import io
import os
import sys

def write_rr_page(f, is_64, is_replay):
    # The length of each code sequence must be RR_PAGE_SYSCALL_STUB_SIZE.
    # The end of each syscall instruction must be at offset
    # RR_PAGE_SYSCALL_INSTRUCTION_END.
    if is_64:
        bytes = bytearray([
            0x0f, 0x05, # syscall
            0xc3, # ret
        ])
    else:
        bytes = bytearray([
            0xcd, 0x80, # int 0x80
            0xc3, # ret
        ])
    # traced
    f.write(bytes)
    # privileged traced
    f.write(bytes)
    # untraced replayed
    f.write(bytes)
    if is_replay:
        # regular untraced syscalls are not executed during replay.
        # Instead we just emulate success.
        bytes[0] = 0x31
        bytes[1] = 0xc0 # xor %eax,%eax
    # untraced
    f.write(bytes)
    # privileged untraced
    f.write(bytes)
    bytes = bytearray([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    f.write(bytes)

generators_for = {
    'rr_page_32': lambda stream: write_rr_page(stream, False, False),
    'rr_page_64': lambda stream: write_rr_page(stream, True, False),
    'rr_page_32_replay': lambda stream: write_rr_page(stream, False, True),
    'rr_page_64_replay': lambda stream: write_rr_page(stream, True, True),
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
