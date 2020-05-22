from util import *

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('stepi')

send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
