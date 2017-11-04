from util import *

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('break traced_raw_syscall')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2')

send_gdb('where')
expect_gdb(' main ')

ok()
