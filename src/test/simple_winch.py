from util import *

# Signal all processes in the process group
send_gdb('!kill -WINCH 0')
send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('run')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('!kill -WINCH 0')
send_gdb('reverse-cont')
expect_gdb('stopped')

ok()
