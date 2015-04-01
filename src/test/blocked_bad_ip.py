from rrutil import *

send_gdb('c\n')
expect_rr('EXIT-SUCCESS')
expect_gdb('SIGSEGV')

send_gdb('reverse-stepi\n')
expect_gdb('SIGSEGV')

send_gdb('reverse-stepi\n')
expect_gdb('start_thread')

ok()
