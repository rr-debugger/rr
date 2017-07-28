from util import *

send_gdb('handle SIGKILL stop')

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('SIGKILL')
# This should not hang
send_gdb('reverse-stepi')
send_gdb('reverse-continue')
expect_gdb('Breakpoint 1')

ok()
