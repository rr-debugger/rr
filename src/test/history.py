from util import *

send_gdb('b breakpointA')
expect_gdb('Breakpoint 1')
send_gdb('c')

expect_gdb('i=0')
send_gdb('c')
expect_gdb('i=1')
send_gdb('c')
expect_gdb('i=2')
send_gdb('c')
expect_gdb('i=3')
send_gdb('c')
expect_gdb('i=4')

send_gdb('forward')
expect_gdb("Can't go forward. No more history entries.")

send_gdb('back')
expect_gdb('i=3')
send_gdb('back')
expect_gdb('i=2')
send_gdb('back')
expect_gdb('i=1')

# A diversion should not interfere with the history
send_gdb('call strlen("abcd")')

send_gdb('back')
expect_gdb('i=0')

# Clear the forward stack by pushing a new entry
send_gdb('c')
expect_gdb('i=1')
send_gdb('forward')
expect_gdb("Can't go forward. No more history entries.")

send_gdb('back')
expect_gdb('i=0')

send_gdb('d 1')
expect_gdb('c')

ok()
