from rrutil import *

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('rwatch -l *(int*)$pc')
expect_gdb('Hardware read watchpoint 2')

send_gdb('continue')
expect_gdb('Hardware read watchpoint 2')

ok()
