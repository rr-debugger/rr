from rrutil import *

restart_replay()
send_gdb('c\n')
expect_rr('EXIT-SUCCESS')

ok()
