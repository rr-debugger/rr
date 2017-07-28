from util import *

send_gdb('watch -l x')
expect_gdb('Hardware[()/a-z ]+watchpoint 1')

send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb('New value = 1')

send_gdb('c')
expect_gdb('Old value = 1')
expect_gdb('New value = -1931448864')

send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
