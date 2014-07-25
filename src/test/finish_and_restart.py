from rrutil import *
import re

send_gdb('c\n')
expect_gdb('EXIT-SUCCESS')
restart_replay_at_end()
index = expect_list([re.compile(r'EXIT-SUCCESS'), re.compile(r'ERROR')])
if index > 0:
    failed('ERROR detected in rr output')
ok()
