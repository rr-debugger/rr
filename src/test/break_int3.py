from rrutil import *

send_gdb('b int3.c:3\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, breakpoint')

ok()
