from rrutil import *

send_gdb('break breakpoint\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')
send_gdb('finish\n')

send_gdb('watch -l *(&v - 1000000)\n')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c\n')
expect_gdb('signal SIGSEGV')

send_gdb('c\n')
expect_gdb('exited normally')

ok()
