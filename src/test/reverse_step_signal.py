from util import *
import re

send_gdb('watch num_signals_caught')
expect_gdb('Hardware watchpoint 1')

send_gdb('c')
expect_gdb('received signal')

send_gdb('c')
expect_gdb('Hardware watchpoint 1')
expect_gdb('Old value = 0')
expect_gdb('New value = 1')

send_gdb('reverse-continue')
expect_gdb('Hardware watchpoint 1')
expect_gdb('Old value = 1')
expect_gdb('New value = 0')

send_gdb('reverse-finish')
expect_gdb('raise')

send_gdb('reverse-stepi')
expect_gdb('received signal')

send_gdb('reverse-continue')
expect_gdb('stopped')

ok()
