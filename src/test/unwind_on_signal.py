from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('p (int)strdup(0)')
expect_gdb('received signal SIGSEGV')
send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('SIGKILL')

ok()
