from util import *
import re

# Setup breakpoints
send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('b breakpoint2')
expect_gdb('Breakpoint 2')
send_gdb('b breakpoint3')
expect_gdb('Breakpoint 3')

# Empty checkpoint list
send_gdb('info checkpoint')
expect_gdb('No checkpoints.')

# Create checkpoint at each breakpoint
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('checkpoint')
index = expect_list([re.compile(r'Checkpoint 1 at .*'), re.compile(r'ERROR')])
if index > 0:
    failed('ERROR detected in rr output')
send_gdb('c')
expect_gdb('Breakpoint 2, breakpoint2')
send_gdb('checkpoint')
expect_gdb('Checkpoint 2 at')
send_gdb('c')
expect_gdb('Breakpoint 3, breakpoint3')
send_gdb('checkpoint')
expect_gdb('Checkpoint 3 at')

# Checkpoint list
send_gdb('info checkpoint')
expect_gdb('ID\tWhen\tWhere')
expect_gdb('1\t')
expect_gdb('2\t')
expect_gdb('3\t')

# Resume checkpoints: each one stops at its breakpoint
send_gdb("restart 1");
expect_gdb('stopped')
send_gdb('c')
expect_gdb('Breakpoint 2, breakpoint2')
send_gdb("restart 3");
expect_gdb('stopped')
send_gdb('c')
expect_rr('exited normally')
send_gdb("restart 2");
expect_gdb('stopped')
send_gdb('c')
expect_gdb('Breakpoint 3, breakpoint3')

# Bare 'run' defaults to last resumed checkpoint
restart_replay()
expect_gdb('Breakpoint 3, breakpoint3')

# Remove checkpoint 2 and try resuming it; it should fail
send_gdb('delete checkpoint 2')
send_gdb("restart 2");
send_gdb('c')
expect_gdb('failed')

ok()
