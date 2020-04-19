#!/usr/bin/env python3

import io
import os
import sys

# Currently the rr page is not copied into the trace. If you want to change
# the contents of the rr page, think carefully about trace compatibility.
# One option would be to save the (replay) rr page into the trace and have
# replay default to the old rr page if the saved page is not present.

def write_rr_page(f, is_64, is_arm, is_replay):
    # The length of each code sequence must be RR_PAGE_SYSCALL_STUB_SIZE.
    # The end of each syscall instruction must be at offset
    # RR_PAGE_SYSCALL_INSTRUCTION_END.
    if is_arm:
        bytes = bytearray([
            0x1, 0x0, 0x0, 0xd4, # svc #0
            0xc0, 0x03, 0x5f, 0xd6, # ret
        ])
        nocall_bytes = bytearray([
            0x0, 0x0, 0x80, 0xd2, # movz x0, #0
            0xc0, 0x03, 0x5f, 0xd6, # ret
        ])
        trap_bytes = bytearray([
            0x0, 0x0, 0x20, 0xd4, # brk #0
            0xc0, 0x03, 0x5f, 0xd6, # ret
        ])
    else:
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
        nocall_bytes = bytearray([
            0x31, 0xc0, # xor %eax,%eax
            0xc3, # ret
        ])
        trap_bytes = bytearray([
            0x90, # nop
            0xcc, # int3
            0xc3, # ret
        ])

    # traced
    f.write(bytes)
    # privileged traced
    f.write(bytes)

    # untraced
    f.write(bytes)
    # untraced replay-only
    if is_replay:
        f.write(bytes)
    else:
        f.write(nocall_bytes)
    # untraced record-only
    if is_replay:
        f.write(nocall_bytes)
    else:
        f.write(bytes)

    # privileged untraced
    f.write(bytes)
    # privileged untraced replay-only
    if is_replay:
        f.write(bytes)
    else:
        f.write(nocall_bytes)
    # privileged untraced record-only
    if is_replay:
        f.write(nocall_bytes)
    else:
        f.write(bytes)

    # untraced replay assist
    if is_replay:
        f.write(trap_bytes)
    else:
        f.write(bytes)

    ff_bytes = bytearray([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    f.write(ff_bytes)

generators_for = {
    'rr_page_32': lambda stream: write_rr_page(stream, False, False, False),
    'rr_page_64': lambda stream: write_rr_page(stream, True, False, False),
    'rr_page_arm64': lambda stream: write_rr_page(stream, True, True, False),
    'rr_page_32_replay': lambda stream: write_rr_page(stream, False, False, True),
    'rr_page_64_replay': lambda stream: write_rr_page(stream, True, False, True),
    'rr_page_arm64_replay': lambda stream: write_rr_page(stream, True, True, True),
}

def main(argv):
    filename = argv[0]
    base = os.path.basename(filename)

    if os.access(filename, os.F_OK):
        with open(filename, 'rb') as f:
            before = f.read()
    else:
        before = ""

    stream = io.BytesIO()
    generators_for[base](stream)
    after = stream.getvalue()
    stream.close()

    if before != after:
        with open(filename, 'wb') as f:
            f.write(after)

if __name__ == '__main__':
    main(sys.argv[1:])
