from rrutil import *

send_gdb('b __libc_start_main\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1')

ok()
