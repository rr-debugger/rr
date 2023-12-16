from util import *

send_gdb('c')
send_gdb('checkpoint')
expect_gdb('is not being run')

send_gdb('b main')
expect_gdb('Breakpoint 1')
restart_replay()
expect_gdb('Breakpoint 1')
send_gdb('b atomic_puts')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2')

send_gdb('checkpoint')
expect_gdb('Checkpoint 1 at')
send_gdb('restart 8')

send_gdb('info threads')
# Don't expect anything specific from 'info threads', but make sure gdb at least functions
send_gdb('p 987654321+1')
expect_gdb('987654322')

send_gdb('restart -1')
send_gdb('restart abc')
send_gdb('restart 1')
expect_gdb('stopped')
send_gdb('c')
# If rr crashes, a 'restart' will re-run the program directly under gdb from
# the beginning. If that happens, we'll stop at breakpoint 1, not exit normally.
expect_gdb('xited normally')

ok()
