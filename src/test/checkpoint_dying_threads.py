from rrutil import *

send_gdb('break breakpoint\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('checkpoint\n')
send_gdb('c\n')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
