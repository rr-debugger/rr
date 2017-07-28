from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('watch -l *(int*)$pc')
expect_gdb('Hardware watchpoint 2')

send_gdb('reverse-continue')
expect_gdb('stopped')

ok()
