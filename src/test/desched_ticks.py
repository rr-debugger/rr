from rrutil import *

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('b __before_poll_syscall_breakpoint')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2')
# This is testing that we can reverse-step without crashing rr.
send_gdb('reverse-stepi')
send_gdb('c')
expect_gdb('Breakpoint 2')

ok()
