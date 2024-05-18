import re

from util import *

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('finish')

send_gdb('watch -l buf[100]')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb(re.compile('New value = ([0-9]+)'))
value = eval(last_match().group(1))
# gcc/gdb on Ubuntu 24 LTS Aarch64 produce 84 here.
# I think it's a gdb bug, using the wrong frame base.
# The value of i is also incorrect in gdb (always zero).
if value != 100 and value != 84:
    failed('Unexpected value')

ok()
