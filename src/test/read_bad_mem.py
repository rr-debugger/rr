from rrutil import *

send_gdb('b main\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, main')

send_gdb('p *0xf\n')
expect_gdb('Cannot access memory at address 0xf')

send_gdb('p *0xffffffff\n')
expect_gdb('Cannot access memory at address 0xffffffff')

ok()
