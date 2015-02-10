from rrutil import *

send_gdb('break atomic_puts\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('reverse-finish\n')
expect_gdb('main')

ok()
