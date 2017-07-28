from util import *

send_gdb('b write')
# "Make breakpoint pending on future shared library load?"
send_gdb('y')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

ok()
