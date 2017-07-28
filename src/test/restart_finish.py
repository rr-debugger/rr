from util import *
import re

restart_replay()
send_gdb('c')
# A stop fires when we hit an exec
expect_rr([ re.compile(r'exited normally'),
            re.compile(r'stopped') ])

ok()
