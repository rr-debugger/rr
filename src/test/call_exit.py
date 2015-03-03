from rrutil import *

send_gdb('b main\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, main')

send_gdb('call exit(0)\n')
expect_gdb('while in a function called from GDB')

restart_replay()
expect_gdb('Breakpoint 1, main')

ok()
