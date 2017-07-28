from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('check')
expect_gdb('Checkpoint 1 at')

send_gdb('p atomic_printf("hello%s", "kitty")')
expect_gdb('hellokitty')

restart_replay()
expect_gdb('Breakpoint 1')

send_gdb('p atomic_printf("hello%s", "kitty")')
expect_gdb('hellokitty')

send_gdb('restart 1')
expect_gdb('stopped')
send_gdb('c')
expect_rr('EXIT-SUCCESS')

ok()
