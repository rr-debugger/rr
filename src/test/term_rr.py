from util import *

send_gdb('handle SIGKILL stop')
send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('SIGKILL')

ok()
