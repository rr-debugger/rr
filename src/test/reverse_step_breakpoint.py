from rrutil import *

send_gdb('b main\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('n\n')
send_gdb('break\n')
expect_gdb('Breakpoint 2')

send_gdb('reverse-next\n')
expect_gdb('Breakpoint 1')

send_gdb('next\n')
expect_gdb('Breakpoint 2')

ok()
