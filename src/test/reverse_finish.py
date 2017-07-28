from util import *

send_gdb('break atomic_puts')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1') 

send_gdb('reverse-finish')
expect_gdb('main')

ok()
