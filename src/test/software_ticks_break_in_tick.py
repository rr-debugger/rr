from util import *
import re

send_gdb('break *tick_bp')
expect_gdb('Breakpoint 1')
while True:
    send_gdb('c')
    if expect_list([re.compile(r'Breakpoint 1, '), re.compile(r'exited normally')]) == 1:
        break
ok()
