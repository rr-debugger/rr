from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('b atomic_puts')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2')

send_gdb('checkpoint')
expect_gdb('Checkpoint 1 at')
send_gdb('restart 8')
send_gdb('restart -1')
send_gdb('restart abc')
send_gdb('restart 1')
expect_gdb('stopped')
send_gdb('c')
# If rr crashes, a 'restart' will re-run the program directly under gdb from
# the beginning. If that happens, we'll stop at breakpoint 1, not exit normally.
expect_gdb('xited normally')

ok()
