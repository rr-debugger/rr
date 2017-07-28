from util import *
import re

NUM_THREADS = 10

send_gdb('b hit_barrier')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, hit_barrier')

arch = get_exe_arch()

# The locations the threads are stopped at depends on the architecture.
stopped_locations = {
    # on i386, we sometimes stop in the middle of nowhere
    'i386': ['(0x[0-9a-f]+ in )?__kernel_vsyscall',
             '(0x[0-9a-f]+ in )?_traced_raw_syscall',
             '0x[0-9a-f]+ in \?\?',
             '(0x[0-9a-f]+ in )?__lll_lock_wait',
             '(0x[0-9a-f]+ in )?pthread_barrier_wait',
             '(0x[0-9a-f]+ in )?futex_wait'],
    'i386:x86-64': ['(0x[0-9a-f]+ in )?__lll_lock_wait',
                    '(0x[0-9a-f]+ in )?pthread_barrier_wait',
                    '(0x[0-9a-f]+ in )?futex_wait',
                    '0x0*70000002 in \?\?'],
}

for i in xrange(NUM_THREADS + 1, 1, -1):
    # The threads are at the kernel syscall entry, or either the
    # traced/untraced entry reached through the rr monkeypatched one.
    # Rarely, non-main threads have been observed to be reordered (i.e. gdb
    # did not number them in order of creation). This does not seem to be a bug
    # so tolerate it.
    send_gdb('info threads')
    expect_gdb(r'%d\s+Thread[^(]+\(BP-THREAD-[0-9]+\) (?:%s)'%
               (i, '|'.join(stopped_locations[arch])))
    expect_gdb(r'\(rr\)')

send_gdb('info threads')
expect_gdb(r'1\s+Thread[^h]+hit_barrier \(\)')

ok()
