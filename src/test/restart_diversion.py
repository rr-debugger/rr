from rrutil import *

send_gdb('b main')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('check')
expect_gdb('= 1')

send_gdb('p atomic_printf("hello%s", "kitty")')
expect_gdb('hellokitty')

restart_replay()
expect_gdb('Breakpoint 1')

send_gdb('p atomic_printf("hello%s", "kitty")')
expect_gdb('hellokitty')

send_gdb('restart 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

ok()
