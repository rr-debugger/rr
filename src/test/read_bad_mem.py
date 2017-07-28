from util import *

send_gdb('b main')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, main')

send_gdb('p *0xf')
expect_gdb('Cannot access memory at address 0xf')

send_gdb('p *0xffffffff')
expect_gdb('Cannot access memory at address 0xffffffff')

ok()
