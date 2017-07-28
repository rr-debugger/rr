from util import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')
# Now we should be in the clone() thread. checkpoint here.
send_gdb('checkpoint')
expect_gdb('Checkpoint 1 at')
send_gdb('restart 1')
expect_gdb('stopped')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('c')
expect_gdb('EXIT-SUCCESS')

ok()
