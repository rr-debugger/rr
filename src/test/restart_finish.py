from rrutil import *
import re

restart_replay()
send_gdb('c')
# SIGTRAP fires when we hit an exec
expect_rr([ re.compile(r'exited normally'),
            re.compile(r'SIGTRAP') ])

ok()
