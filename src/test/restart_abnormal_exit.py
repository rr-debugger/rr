from rrutil import *

send_gdb('c\n')
expect_gdb('exited')

restart_replay()
expect_gdb('exited')

restart_replay()
expect_gdb('exited')

ok()
