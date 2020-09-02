from util import *

send_gdb('break do_checkpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('checkpoint')
expect_gdb('Checkpoint 1')
send_gdb('c')
expect_gdb('xited normally')
send_gdb('restart 1')
expect_gdb('stopped')
send_gdb('c')
expect_gdb('xited normally')
send_gdb('c')

ok()
