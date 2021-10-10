from util import *

send_gdb('b sighandler')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Program received signal SIGILL')

send_gdb('c')
expect_gdb('Breakpoint 1, sighandler')

ok()
