from util import *
import re

send_gdb('break atomic_puts')
expect_gdb('Breakpoint 1')
send_gdb('continue')
expect_gdb('Breakpoint 1')
send_gdb('hbreak main')
expect_gdb('breakpoint 2')
send_gdb('reverse-continue')
expect_gdb('Breakpoint 2')

ok()
