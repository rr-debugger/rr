from rrutil import *

send_gdb('c\n')
expect_gdb('exited normally')

restart_replay()

expect_gdb('exited normally')

ok()
