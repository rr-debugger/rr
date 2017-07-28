from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('call crash()')
expect_gdb('SIGSEGV')
restart_replay()
expect_gdb('Breakpoint 1')

ok()
