from rrutil import *

send_gdb('c\n')
expect_gdb('Program received signal SIGUSR1')

send_gdb('c\n')
expect_gdb('exited normally')

ok()
