from rrutil import *

send_gdb('b breakpoint\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('c\n')
expect_gdb('Breakpoint 1, breakpoint')
# Now we should be in the clone() thread. checkpoint here.
send_gdb('checkpoint\n');
expect_gdb('= 1')
send_gdb('restart 1\n');
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('c\n')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('c\n')
expect_gdb('EXIT-SUCCESS')

ok()
