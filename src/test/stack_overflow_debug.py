from util import *

send_gdb('handle SIGKILL stop')

send_gdb('c')
expect_gdb('SIGSEGV')
send_gdb('stepi')
expect_gdb('SIGSEGV')
send_gdb('stepi')
expect_gdb('SIGKILL')

send_gdb('reverse-stepi')
expect_gdb('SIGSEGV')
send_gdb('reverse-stepi')
expect_gdb('SIGSEGV')
send_gdb('reverse-continue')
expect_gdb('stopped')

ok()
