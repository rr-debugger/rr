from util import *

send_gdb('c')
expect_gdb('exited normally')

restart_replay()

expect_gdb('exited normally')

ok()
