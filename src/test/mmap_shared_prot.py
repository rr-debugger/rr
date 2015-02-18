from rrutil import *

send_gdb('break breakpoint\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('check\n')
expect_gdb('= 1')

send_gdb('c\n')
expect_gdb('exited normally')

send_gdb('restart 1\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('exited normally')

ok()
