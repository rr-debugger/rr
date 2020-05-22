from util import *

send_gdb('break string_store')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('watch -l p[0]')
expect_gdb('watchpoint 2')
send_gdb('c')
expect_gdb('watchpoint 2')

send_gdb('break')
expect_gdb('Breakpoint 3')
send_gdb('disable 3')
send_gdb('finish')
expect_gdb('main')

send_gdb('enable 3')
send_gdb('reverse-continue')
expect_gdb('Breakpoint 3')

ok()
