from rrutil import *

send_gdb('break breakpoint\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')
send_gdb('finish\n')

send_gdb('watch -l buf[100]\n')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c\n')
expect_gdb('Old value = 0')
expect_gdb('New value = 100')

ok()
