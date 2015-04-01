from rrutil import *

send_gdb('break main\n')
expect_gdb('Breakpoint 1')
send_gdb('break breakpoint\n')
expect_gdb('Breakpoint 2')

send_gdb('c\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 2')

send_gdb('reverse-continue\n')
expect_gdb('Breakpoint 1')

ok()
