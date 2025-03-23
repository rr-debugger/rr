from util import *

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('p &var')
expect_gdb(r'\$1 = \(volatile int \*\) ')

send_gdb('watch *$1')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

send_gdb('reverse-stepi')
expect_gdb('Old value = 42')
expect_gdb('New value = 0')

send_gdb('stepi')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

ok()
