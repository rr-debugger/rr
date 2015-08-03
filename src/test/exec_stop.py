from rrutil import *
import re

send_gdb('c')
expect_gdb('SIGTRAP')
send_gdb('stepi')
send_gdb('stepi')
send_gdb('c')
expect_gdb('SIGTRAP')
send_gdb('b execve')
expect_gdb('Breakpoint 1')
send_gdb('rc')
expect_gdb('Breakpoint 1')

ok()
