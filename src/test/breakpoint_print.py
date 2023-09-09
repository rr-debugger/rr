from util import *
import re

send_gdb('b main')
expect_gdb('Breakpoint 1')

send_gdb('commands 1')
send_gdb('print 123 + 456')
send_gdb('end')

send_gdb('c')
# Old gdbs print 579 before 'Breakpoint 1'
# expect_gdb('Breakpoint 1')
expect_gdb('579')

ok()
