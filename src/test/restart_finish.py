from rrutil import *

restart_replay()
send_gdb('c')
expect_rr('exited normally')

ok()
