from rrutil import *
import re

NUM_THREADS = 10

send_gdb('b hit_barrier\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, hit_barrier')

send_gdb('info threads\n')
for i in xrange(NUM_THREADS + 1, 1, -1):
    # The threads are at the kernel syscall entry, or either the
    # traced/untraced entry reached through the rr monkeypatched one.
    expect_gdb(r'%d\s+Thread[^(]+\(BP-THREAD-%d\)[^_]+(?:__kernel_vsyscall|_traced_raw_syscall|_untraced_syscall_entry_point_ip) \(\)'%
               (i, i))

expect_gdb(r'1\s+Thread[^h]+hit_barrier \(\)')

ok()
