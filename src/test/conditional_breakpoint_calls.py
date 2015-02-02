import re
from rrutil import *

send_gdb('b print_dot if checker()\n')
expect_gdb('Breakpoint 1')
send_gdb('watch dot_counter if checker()\n')
expect_gdb('Hardware watchpoint 2')
send_gdb('c\n')
expect_rr('EXIT-SUCCESS')

ok()
