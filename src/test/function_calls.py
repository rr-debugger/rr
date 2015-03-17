from rrutil import *

send_gdb('break main\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('n\n');
send_gdb('n\n');
send_gdb('reverse-next\n');
send_gdb('c\n');

expect_gdb('exited normally')

ok()
