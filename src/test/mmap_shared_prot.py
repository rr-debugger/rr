from rrutil import *

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('check')
expect_gdb('= 1')

send_gdb('c')
expect_gdb('exited normally')

send_gdb('restart 1')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('exited normally')

ok()
