from util import *

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('break breakpoint')
expect_gdb('Breakpoint 2')

send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 2')

send_gdb('reverse-continue')
expect_gdb('Breakpoint 1')

ok()
