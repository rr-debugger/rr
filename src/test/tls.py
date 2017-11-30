from util import *

send_gdb('break breakpoint_fn')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('print tlsvar')
expect_gdb(' = 97')

send_gdb('reverse-stepi')
send_gdb('print tlsvar')
expect_gdb(' = 97')

ok()
