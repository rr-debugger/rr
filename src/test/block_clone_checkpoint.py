from util import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('checkpoint')
expect_gdb('Checkpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('restart 1')
expect_gdb('breakpoint')

send_gdb('disable')
send_gdb('c')
expect_rr('EXIT-SUCCESS')

ok()
