from util import *

send_gdb('handle SIGKILL stop')

# Test that invalid syntax doesn't crash rr
send_gdb('run run 100')
send_gdb('y')
send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

# Running with a big event number should reach the end of the recording
send_gdb('run 10000')
send_gdb('y')
expect_gdb('SIGKILL')
send_gdb('c')
expect_gdb('xited normally')

send_gdb('run 10000')
# no need to confirm since the process already exited
expect_gdb('SIGKILL')
send_gdb('reverse-cont')
expect_gdb('Breakpoint 1')

ok()
