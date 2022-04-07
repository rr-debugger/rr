from util import *

send_gdb('handle SIGKILL stop')
send_gdb('handle SIGTERM stop')
send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('received signal SIGTERM')
send_gdb('c')
expect_gdb('received signal SIGKILL')

ok()
