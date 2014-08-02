from rrutil import *

send_gdb('b main\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('check\n')
expect_gdb('= 1')

send_gdb('p atomic_printf("hello%s", "kitty")\n')
expect_gdb('hellokitty')

restart_replay()
expect_gdb('Breakpoint 1')

send_gdb('p atomic_printf("hello%s", "kitty")\n')
expect_gdb('hellokitty')

send_gdb('restart 1\n')
expect_gdb('Breakpoint 1')

ok()
