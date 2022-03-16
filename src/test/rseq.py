from util import *

send_gdb('break abort_ip')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('reverse-stepi')
send_gdb('stepi')
send_gdb('stepi')
expect_gdb('Breakpoint 1')

send_gdb('disable 1')
send_gdb('c')
expect_gdb('rogram stopped')

ok()
