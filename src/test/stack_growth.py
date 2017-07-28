from util import *

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('finish')

send_gdb('watch -l buf[100]')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb('New value = 100')

ok()
