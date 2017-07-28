from util import *

send_gdb('b C')
expect_gdb('Breakpoint 1')

send_gdb('b main')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2, main')

send_gdb('cond 1 rand()&1 < 10')

send_gdb('c')

expect_rr('calling C')

expect_gdb('Breakpoint 1, C')

send_gdb('check')
send_gdb('c')
expect_rr('finished C')

ok()
