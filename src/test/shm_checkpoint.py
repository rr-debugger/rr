from util import *

send_gdb('b before_writing')
expect_gdb('Breakpoint 1')

send_gdb('b after_writing')
expect_gdb('Breakpoint 2')

send_gdb('c');
expect_gdb('Breakpoint 1, before_writing')

send_gdb('checkpoint');
expect_gdb('Checkpoint 1 at');

send_gdb('c');
expect_gdb('Breakpoint 2, after_writing')

send_gdb('restart 1');
expect_gdb('stopped')
send_gdb('c');
expect_gdb('Breakpoint 2, after_writing')

ok()

