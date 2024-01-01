import os
from util import *

EVENTS = int(os.environ['EVENTS'])

send_gdb('when')
expect_gdb('Completed event: 1000')

send_gdb('b first_breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('b second_breakpoint')
expect_gdb('Breakpoint 2')

send_gdb('c')
# If we hit first_breakpoint, then we never continue and never reach
# second_breakpoint.
expect_gdb('Breakpoint 2, second_breakpoint')

restart_replay(1)
expect_gdb('Breakpoint 1, first_breakpoint')

ok()
