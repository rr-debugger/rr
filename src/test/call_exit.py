from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, main')

send_gdb('call (int)exit(0)')
expect_gdb('while in a function called from GDB')

restart_replay()
expect_gdb('Breakpoint 1, main')

ok()
