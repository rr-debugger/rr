from util import *

send_gdb('handle SIGURG noprint nostop pass')
send_gdb('handle SIGKILL stop')

send_gdb('c')


expect_rr('XIT-END')

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('reverse-continue')

expect_gdb('Breakpoint 1')
ok()