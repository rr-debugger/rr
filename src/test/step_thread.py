import re
from util import *

send_gdb('set scheduler-locking off')

send_gdb('b hit_barrier')
expect_gdb('Breakpoint 1')

send_gdb('b ready')
expect_gdb('Breakpoint 2')

send_gdb('c')
expect_gdb('Breakpoint 2, ready')

bps = set(('A', 'B', 'C'))
for bp in bps:
    send_gdb('b '+ bp +'')
    expect_gdb('Breakpoint \d')

expect_gdb(r'\(rr\)')

hit_bps = { 'A': 0, 'B': 0, 'C': 0 }

events = [ re.compile(r'Breakpoint 1, hit_barrier'),
           re.compile(r'Breakpoint \d, ([ABC])'),
           re.compile(r'Remote connection closed'),
           re.compile(r'internal-error:'),
           re.compile(r'Cannot find bounds of current function'),
           re.compile(r'\(rr\)') ]
next_cmd = 's'
while 1:
    send_gdb(next_cmd)
    next_cmd = 's'
    i = expect_list(events)
    if 0 == i:
        break
    if 2 == i or 3 == i:
        assert False, 'Program stopped unexpectedly, review gdb_rr.log'
    if 4 == i:
        expect_gdb(r'\(rr\)')
        next_cmd = 'stepi'
        continue
    if 5 == i:
        continue

    bp = last_match().group(1)
    assert not hit_bps[bp]
    hit_bps[bp] = 1
    expect_gdb(r'\(rr\)')

for bp in hit_bps.iterkeys():
    assert hit_bps[bp]

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

location_regex = '|'.join(stopped_locations[arch])

send_gdb('info threads')
expect_gdb(r'1\s+Thread.+hit_barrier')
expect_gdb(r'\(rr\)')

send_gdb('info threads')
expect_gdb(r'2\s+Thread.+?(?:%s)' % location_regex)
expect_gdb(r'\(rr\)')

send_gdb('info threads')
expect_gdb(r'3\s+Thread.+?(?:%s)' % location_regex)
expect_gdb(r'\(rr\)')

ok()
