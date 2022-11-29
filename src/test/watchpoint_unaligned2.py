from util import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('watch -l value.high')
expect_gdb('Hardware watchpoint 2')
send_gdb('c')
expect_gdb('watchpoint 2')
send_gdb('delete 2')

ok()
