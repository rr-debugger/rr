from rrutil import *
import re

send_gdb('watch num_signals_caught\n')
expect_gdb('Hardware watchpoint 1')

send_gdb('c\n')
expect_gdb('received signal')

send_gdb('c\n')
expect_gdb('Hardware watchpoint 1')
expect_gdb('Old value = 0')
expect_gdb('New value = 1')

send_gdb('reverse-continue\n')
expect_gdb('Hardware watchpoint 1')
expect_gdb('Old value = 1')
expect_gdb('New value = 0')

send_gdb('reverse-finish\n')
expect_gdb('raise')

send_gdb('reverse-stepi\n')
expect_gdb('received signal')

send_gdb('reverse-continue\n')
expect_gdb('exited normally')

ok()
