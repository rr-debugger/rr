from rrutil import *

send_gdb('b hit_barrier\n')
expect_gdb('Breakpoint 1')

bps = set(('A', 'B', 'C'))
for bp in bps:
    send_gdb('b '+ bp +'\n')
    expect_gdb('Breakpoint \d')

send_gdb('c\n')

for i in xrange(0, len(bps)):
    expect_gdb('Breakpoint \d, [ABC] \(\)')

    send_gdb('n\n')
    send_gdb('c\n')

expect_gdb('Breakpoint 1, hit_barrier')

send_gdb('info threads\n')
# Main thread and two other threads
for i in xrange(3, 1, -1):
    # The threads are at the vdso, hence the '??' top frame.
    expect_gdb(str(i) + r'\s+Thread[^t]+\?\? \(\)')

ok()
