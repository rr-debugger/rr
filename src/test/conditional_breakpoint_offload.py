from util import *

send_gdb('handle SIGKILL stop')

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('cond 1 var==-1')

send_gdb('b main')
expect_gdb('Breakpoint 2')

send_gdb('c')
expect_gdb('Breakpoint 2')
send_gdb('c')
# This should complete in a reasonable amount of time!
expect_gdb('SIGKILL')

send_gdb('reverse-continue')
# And so should this!
expect_gdb('Breakpoint 2')

ok()
