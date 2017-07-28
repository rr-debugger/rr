from util import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('watch -l *p2')
expect_gdb('Hardware watchpoint 2')
send_gdb('c')
expect_gdb('watchpoint 2')
send_gdb('delete 2')

send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('watch -l *p4')
expect_gdb('Hardware watchpoint 3')
send_gdb('c')
expect_gdb('watchpoint 3')
send_gdb('delete 3')

send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('watch -l *p8')
expect_gdb('Hardware watchpoint 4')
send_gdb('c')
expect_gdb('watchpoint 4')
send_gdb('delete 4')

ok()
