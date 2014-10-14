import re
from rrutil import *

send_gdb('b hit_barrier\n')
expect_gdb('Breakpoint 1')

send_gdb('b ready\n')
expect_gdb('Breakpoint 2')

send_gdb('c\n')
expect_gdb('Breakpoint 2, ready')

bps = set(('A', 'B', 'C'))
for bp in bps:
    send_gdb('b '+ bp +'\n')
    expect_gdb('Breakpoint \d')

expect_gdb(r'\(gdb\)')

hit_bps = { 'A': 0, 'B': 0, 'C': 0 }

events = [ re.compile(r'Breakpoint 1, hit_barrier'),
           re.compile(r'Breakpoint \d, ([ABC])'),
           re.compile(r'\(gdb\)') ]
while 1:
    send_gdb('s\n')
    i = expect_list(events)
    if 0 == i:
        break
    if 2 == i:
        continue

    bp = last_match().group(1)
    assert not hit_bps[bp]
    hit_bps[bp] = 1
    expect_gdb(r'\(gdb\)')

for bp in hit_bps.iterkeys():
    assert hit_bps[bp]

arch = get_exe_arch()

# The locations the threads are stopped at depends on the architecture.
stopped_locations = {
    'i386': ['__kernel_vsyscall', '_traced_raw_syscall'],
    'i386:x86-64': ['__lll_lock_wait', 'pthread_barrier_wait'],
}

location_regex = '|'.join(stopped_locations[arch])

send_gdb('info threads\n')
expect_gdb(r'3\s+Thread.+?(?:%s)' % location_regex)
expect_gdb(r'2\s+Thread.+?(?:%s)' % location_regex)
expect_gdb(r'1\s+Thread.+hit_barrier')

ok()
