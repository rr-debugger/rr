from rrutil import *

send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited')

send_gdb('b main')
expect_gdb('Breakpoint 1')

restart_replay()
expect_gdb('Breakpoint 1')
send_gdb('checkpoint')
expect_gdb('= 1')
send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited')

restart_replay()
expect_gdb('Breakpoint 1')
send_gdb('checkpoint')
expect_gdb('= 2')
send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited')

ok()
