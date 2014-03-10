from rrutil import *

send_gdb('b bad_breakpoint\n')
expect_gdb('Breakpoint 1')

send_gdb('b good_breakpoint\n')
expect_gdb('Breakpoint 2')

send_gdb('c\n')
# If we hit bad_breakpoint, then we never continue and never reach
# good_breakpoint.
expect_gdb('Breakpoint 2, good_breakpoint')

restart_replay(1)
expect_gdb('Breakpoint 2, good_breakpoint')

ok()
