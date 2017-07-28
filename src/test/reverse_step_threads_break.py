from util import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('b breakpoint_thread')
expect_gdb('Breakpoint 2')

send_gdb('set scheduler-locking off')
for i in xrange(50):
  send_gdb('reverse-step')

expect_gdb('Breakpoint 2')

ok()
