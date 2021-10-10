from util import *

send_gdb('break string_store')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('disable')
send_gdb('watch -l p[0]')
expect_gdb('watchpoint')
send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb('New value = 1')
send_gdb('p p[0]')
expect_gdb('= 1')
send_gdb('p p[1]')
expect_gdb('= 0')

ok()
