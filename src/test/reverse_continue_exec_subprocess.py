from util import *
import re

send_gdb('reverse-cont')
expect_history_end()
send_gdb('reverse-cont')
expect_history_end()
send_gdb('reverse-stepi')
expect_history_end()
send_gdb('reverse-cont')
expect_history_end()

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('reverse-cont')
expect_history_end()
send_gdb('reverse-cont')
expect_history_end()
send_gdb('reverse-stepi')
expect_history_end()
send_gdb('reverse-cont')
expect_history_end()

ok()
