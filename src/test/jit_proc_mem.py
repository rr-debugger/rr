from util import *

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('up')
send_gdb('b *space')
expect_gdb('Breakpoint 2')

# Should hit breakpoint 2 here rather than making it all the way back to
# the first instance of breakpoint 1.
send_gdb('rc')
expect_gdb('Breakpoint 2')

ok()
