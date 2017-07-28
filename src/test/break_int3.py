from util import *

send_gdb('b int3.c:3')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')

ok()
