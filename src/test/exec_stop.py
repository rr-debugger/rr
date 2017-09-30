from util import *

send_gdb('c')
expect_gdb('stopped')
send_gdb('stepi')
expect_gdb('stopped')
send_gdb('stepi')
expect_gdb('stopped')
send_gdb('c')
expect_gdb('stopped')
send_gdb('b execve')
expect_gdb('Breakpoint 1')
send_gdb('rc')
expect_gdb('Breakpoint 1')

ok()
