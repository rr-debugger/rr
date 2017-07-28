from util import *

send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('SIGSEGV')

send_gdb('reverse-stepi')
expect_gdb('SIGSEGV')

send_gdb('reverse-stepi')
expect_gdb('start_thread')

ok()
