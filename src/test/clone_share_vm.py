from util import *

send_gdb('break break_function')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('check')
expect_gdb('Checkpoint 1')
send_gdb('next')
send_gdb('restart 1')
expect_gdb('break_function')

send_gdb('continue')
expect_rr('EXIT-SUCCESS')

ok()
