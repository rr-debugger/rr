from util import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('set scheduler-locking off')
send_gdb('reverse-step')

send_gdb('c')
expect_gdb('Breakpoint 1')

ok()
