from util import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')

expect_gdb('Breakpoint 1, breakpoint')

send_gdb('call check_pid()')
expect_gdb('SUCCESS')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('call check_tid()')
expect_gdb('SUCCESS')

send_gdb('c')
expect_rr('EXIT-SUCCESS')

ok()
