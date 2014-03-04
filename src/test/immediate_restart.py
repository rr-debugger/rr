from rrutil import *

restart_replay()
expect_rr('Reached target process')
send_gdb('q\n')

ok()
