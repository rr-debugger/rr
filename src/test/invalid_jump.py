from util import *

send_gdb('c')
expect_gdb('Program received signal SIGSEGV')

send_gdb('rsi')
send_gdb('rsi')

expect_gdb('in main')

ok()
