from rrutil import *

send_gdb('b main\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1')

ok()
