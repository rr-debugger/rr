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
    # Rarely, non-main threads have been observed to be reordered (i.e. gdb
    # did not number them in order of creation). This does not seem to be a bug
    # so tolerate it.
    expect_gdb(r'%d\s+Thread[^(]+\(BP-THREAD-[0-9]+\)[^_]+(?:__kernel_vsyscall|_traced_raw_syscall|_untraced_syscall_entry_point_ip) \(\)'%
               (i))

expect_gdb(r'1\s+Thread[^h]+hit_barrier \(\)')

ok()
