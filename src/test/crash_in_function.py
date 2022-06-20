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
expect_gdb('Program terminated with signal SIGKILL')
# gdb forgets that we already stopped at this breakpoint so it'll stop us there again
send_gdb('next')
expect_gdb('Breakpoint 1')

send_gdb('next')
expect_rr('EXIT-SUCCESS')
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
expect_rr('EXIT-SUCCESS')
send_gdb('call crash()')
expect_gdb('SIGSEGV')
send_gdb('c')
expect_gdb('SIGKILL')

ok()
