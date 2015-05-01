from rrutil import *

send_gdb('b __libc_start_main')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

ok()
