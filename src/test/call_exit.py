from rrutil import *

send_gdb('b main\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, main')

send_gdb('call exit(0)\n')
expect_gdb('exited while in a function called from GDB')

send_gdb('run\n')
expect_gdb('Breakpoint 1, main')

ok()
