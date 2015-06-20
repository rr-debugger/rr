from rrutil import *

# Signal all processes in the process group
send_gdb('!kill -WINCH 0\n')
send_gdb('c\n')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

send_gdb('break main\n')
expect_gdb('Breakpoint 1')
send_gdb('run\n')
expect_gdb('Breakpoint 1')
send_gdb('!kill -WINCH 0\n')
send_gdb('reverse-cont\n')
expect_gdb('SIGTRAP')

ok()
