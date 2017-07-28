from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('b mprotect')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2')

# step through mprotect() until we reach the system call that
# gets performed during replay
for i in xrange(0,200):
    send_gdb('stepi')
    expect_gdb('(rr)')

ok()
