from rrutil import *

send_gdb('b breakpoint\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('f 1\n')
expect_gdb('(gdb)')

send_gdb('p big\n')
expect_gdb("  bytes = 'Z'")

ok()
