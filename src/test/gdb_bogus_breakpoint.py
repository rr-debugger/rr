from util import *

send_gdb('break my_write')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('s')

send_gdb('c')
# First E may be printed by itself during 's'
expect_rr('XIT-SUCCESS')
expect_gdb('exited normally')

ok()
