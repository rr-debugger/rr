from util import *

send_gdb('break 48')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('checkpoint')
send_gdb('write-checkpoints')
send_gdb('delete checkpoint 1')
send_gdb('c')

expect_rr('EXIT-SUCCESS')

send_gdb('load-checkpoints')
send_gdb('restart 2')
expect_gdb('Program stopped')

send_gdb('print ptr')
expect_gdb('"hello parenthello child"')

ok()