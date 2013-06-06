from rrutil import *

send_gdb('b halfway_done\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, halfway_done')

ok()
