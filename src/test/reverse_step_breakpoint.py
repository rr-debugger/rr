from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('n')
send_gdb('break')
expect_gdb('Breakpoint 2')

send_gdb('reverse-next')
expect_gdb('Breakpoint 1')

send_gdb('next')
expect_gdb('Breakpoint 2')

ok()
