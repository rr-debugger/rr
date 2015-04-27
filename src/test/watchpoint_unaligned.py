from rrutil import *

send_gdb('b breakpoint\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1')
send_gdb('watch -l *p2\n')
expect_gdb('Hardware watchpoint 2')
send_gdb('c\n')
expect_gdb('watchpoint 2')
send_gdb('delete 2\n')

send_gdb('c\n')
expect_gdb('Breakpoint 1')
send_gdb('watch -l *p4\n')
expect_gdb('Hardware watchpoint 3')
send_gdb('c\n')
expect_gdb('watchpoint 3')
send_gdb('delete 3\n')

send_gdb('c\n')
expect_gdb('Breakpoint 1')
send_gdb('watch -l *p8\n')
expect_gdb('Hardware watchpoint 4')
send_gdb('c\n')
expect_gdb('watchpoint 4')
send_gdb('delete 4\n')

ok()
