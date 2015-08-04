from rrutil import *

send_gdb('b sighandler')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Program received signal SIGILL')
expect_gdb('ud2')

send_gdb('checkpoint')
expect_gdb('= 1')

send_gdb('c')
expect_gdb('Breakpoint 1, sighandler')

send_gdb("restart 1");
expect_gdb('Breakpoint 1, sighandler')

ok()
