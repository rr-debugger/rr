import re
from util import *

send_gdb('b print_dot if checker()')
expect_gdb('Breakpoint 1')
send_gdb('watch dot_counter if checker()')
expect_gdb('Hardware watchpoint 2')
send_gdb('c')
expect_rr('EXIT-SUCCESS')

ok()
