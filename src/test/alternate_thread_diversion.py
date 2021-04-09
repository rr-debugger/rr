from util import *

send_gdb('b break_here')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('info threads')
expect_gdb('  1    Thread')
expect_gdb('\\* 2    Thread')

send_gdb('thread 1')
expect_gdb('Switching to thread 1')
send_gdb('set scheduler-locking on')
send_gdb('call get_value()')
expect_gdb('1')
send_gdb('set scheduler-locking off')
send_gdb('c')
expect_gdb('SIGKILL')

ok()
