from util import *

send_gdb('handle SIGKILL stop')

send_gdb('c')
expect_gdb('SIGKILL')

send_gdb('watch -l x')
expect_gdb('Hardware[()/a-z ]+watchpoint 1')

send_gdb('rc')
expect_gdb('watchpoint 1')
expect_gdb('New value = 1564779003')

ok()
