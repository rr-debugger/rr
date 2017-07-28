from util import *
import re

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('rc')
expect_gdb('Breakpoint 1')

ok()
