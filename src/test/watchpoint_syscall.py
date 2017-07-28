from util import *

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('watch -l *p')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb('New value = 97')

send_gdb('c')
expect_gdb('Old value = 97')
expect_gdb('New value = 0')

send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb('New value = 98')

send_gdb('c')
expect_gdb('Old value = 98')
expect_gdb('New value = 0')

send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb('New value = <unreadable>')

send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
