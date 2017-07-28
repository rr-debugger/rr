from util import *

send_gdb('b spin')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('finish')

send_gdb('set scheduler-locking off')
send_gdb('reverse-step')

send_gdb('reverse-continue')
expect_gdb('Breakpoint 1')

ok()
