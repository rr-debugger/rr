from util import *

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('finish')

send_gdb('watch -l *(&v - 1000000)')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c')
expect_gdb('signal SIGSEGV')

send_gdb('c')
expect_gdb('exited normally')

ok()
