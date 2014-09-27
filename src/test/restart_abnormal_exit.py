from rrutil import *

send_gdb('c\n')
expect_gdb('exited')

send_gdb('run\n')
expect_gdb('exited')

ok()
