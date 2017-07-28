from util import *

send_gdb('b bad_breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('b good_breakpoint')
expect_gdb('Breakpoint 2')

send_gdb('c')
# If we hit bad_breakpoint, then we never continue and never reach
# good_breakpoint.
expect_gdb('Breakpoint 2, good_breakpoint')

ok()
