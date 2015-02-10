from rrutil import *

send_gdb('break atomic_puts\n')
expect_gdb('Breakpoint 1')
send_gdb('watch var\n')
expect_gdb('Hardware watchpoint 2')

send_gdb('c\n')
expect_gdb('Hardware watchpoint 2')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

send_gdb('c\n')
expect_gdb('Hardware watchpoint 2')
expect_gdb('Old value = 42')
expect_gdb('New value = 1337')

send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('reverse-cont\n')
expect_gdb('Hardware watchpoint 2')
expect_gdb('Old value = 1337')
expect_gdb('New value = 42')

send_gdb('reverse-cont\n')
expect_gdb('Hardware watchpoint 2')
expect_gdb('Old value = 42')
expect_gdb('New value = 0')

send_gdb('reverse-cont\n')
expect_gdb('exited normally')

ok()
