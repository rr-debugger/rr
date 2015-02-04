from rrutil import *

send_gdb('b before_writing\n')
expect_gdb('Breakpoint 1')

send_gdb('b after_writing\n')
expect_gdb('Breakpoint 2')

send_gdb('c\n');
expect_gdb('Breakpoint 1, before_writing')

send_gdb('checkpoint\n');
expect_gdb('= 1');

send_gdb('c\n');
expect_gdb('Breakpoint 2, after_writing')

send_gdb('restart 1\n');
expect_gdb('Breakpoint 1, before_writing')

send_gdb('c\n');
expect_gdb('Breakpoint 2, after_writing')

ok()

