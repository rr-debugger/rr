from util import *

send_gdb('handle SIGKILL stop')
send_gdb('set unwindonsignal off')

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('call crash()')
expect_gdb('SIGSEGV')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('next')
send_gdb('call crash()')
expect_gdb('SIGSEGV')
send_gdb('c')
expect_gdb('SIGKILL')

restart_replay()
expect_gdb('Breakpoint 1')
send_gdb('delete 1')
send_gdb('set unwindonsignal on')
send_gdb('call crash()')
expect_gdb('SIGSEGV')

send_gdb('next')
send_gdb('call crash()')
expect_gdb('SIGSEGV')
send_gdb('c')
expect_gdb('SIGKILL')

ok()
