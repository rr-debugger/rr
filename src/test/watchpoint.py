from rrutil import *

send_gdb('p &var\n')
expect_gdb(r'\$1 = \(int \*\) ')

send_gdb('watch *$1\n')
expect_gdb('Hardware watchpoint 1')

send_gdb('c\n')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

send_gdb('c\n')
expect_gdb('Old value = 42')
expect_gdb('New value = 1337')

send_gdb('c\n')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
