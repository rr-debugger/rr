from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, main')

# Step over the breakpoint and into `atomic_puts' to make sure it
# doesn't influence the test.
send_gdb('step')
expect_gdb('atomic_puts \\(str=')

send_gdb('call (int)exit(0)')
expect_gdb('while in a function called from GDB')

# Check sure we're still in the frame of `atomic_puts' and can still
# continue the replay.
send_gdb('finish')
expect_gdb('EXIT-SUCCESS')

restart_replay()
expect_gdb('Breakpoint 1, main')

ok()
