from rrutil import *

send_gdb('c\n')
expect_gdb('Program received signal SIGILL')

ok()
