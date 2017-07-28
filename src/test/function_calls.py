from util import *

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('n');
send_gdb('n');
send_gdb('reverse-next');
send_gdb('c');

expect_gdb('exited normally')

ok()
