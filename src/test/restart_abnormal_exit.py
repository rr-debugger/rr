from util import *

send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited')

send_gdb('b main')
expect_gdb('Breakpoint 1')

restart_replay()
expect_gdb('Breakpoint 1')
send_gdb('checkpoint')
expect_gdb('Checkpoint 1 at')
send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited')

restart_replay()
expect_gdb('Breakpoint 1')
send_gdb('checkpoint')
expect_gdb('Checkpoint 2 at')
send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited')

ok()
