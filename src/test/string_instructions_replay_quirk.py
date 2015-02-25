from rrutil import *

send_gdb('break string_store\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('disable\n')
send_gdb('watch -l p[0]\n')
expect_gdb('watchpoint')
send_gdb('c\n')
expect_gdb('Old value = 0')
expect_gdb('New value = 1')
send_gdb('p p[0]\n')
expect_gdb('= 1')
send_gdb('p p[1]\n')
expect_gdb('= 0')

ok()
