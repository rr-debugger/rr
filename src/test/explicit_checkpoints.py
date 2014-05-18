from rrutil import *

# Setup breakpoints
send_gdb('b main\n')
expect_gdb('Breakpoint 1')
send_gdb('b breakpoint2\n')
expect_gdb('Breakpoint 2')
send_gdb('b breakpoint3\n')
expect_gdb('Breakpoint 3')

# Create checkpoint at each breakpoint
send_gdb('c\n')
expect_gdb('Breakpoint 1, main')
send_gdb('checkpoint\n')
expect_gdb('= 1')
send_gdb('c\n')
expect_gdb('Breakpoint 2, breakpoint2')
send_gdb('checkpoint\n')
expect_gdb('= 2')
send_gdb('c\n')
expect_gdb('Breakpoint 3, breakpoint3')
send_gdb('checkpoint\n')
expect_gdb('= 3')

# Resume checkpoints: each one stops at its breakpoint
send_gdb("restart 1\n");
expect_gdb('Breakpoint 1, main')
send_gdb("restart 3\n");
expect_gdb('Breakpoint 3, breakpoint3')
send_gdb("restart 2\n");
expect_gdb('Breakpoint 2, breakpoint2')

# Bare 'run' defaults to last resumed checkpoint
restart_replay()
expect_gdb('Breakpoint 2, breakpoint2')

# Delete breakpoint 2 and resume checkpoint; should stop
# at breakpoint 3
send_gdb('del 2\n')
send_gdb("restart 2\n");
expect_gdb('Breakpoint 3, breakpoint3')

# Remove checkpoint 2 and try resuming it; it should fail
send_gdb('delete checkpoint 2\n')
send_gdb("restart 2\n");
expect_gdb('failed')

# Resume checkpoint 3 and continue to end; make sure we can resume checkpoint
# after that.
send_gdb("restart 3\n");
expect_gdb('Breakpoint 3, breakpoint3')
send_gdb('c\n')
expect_gdb('exited normally')
send_gdb("restart 3\n");
expect_gdb('Breakpoint 3, breakpoint3')
send_gdb('q\n')

ok()
