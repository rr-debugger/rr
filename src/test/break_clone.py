from rrutil import *

send_gdb('b breakpoint\n')
expect_gdb('Breakpoint 1')

for i in xrange(2):
    send_gdb('c\n')
    expect_gdb('Breakpoint 1, breakpoint')

ok()
