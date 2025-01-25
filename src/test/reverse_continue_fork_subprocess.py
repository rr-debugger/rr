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

send_gdb('stepi')
send_gdb('reverse-cont')
expect_history_end()
send_gdb('reverse-cont')
expect_history_end()
send_gdb('reverse-stepi')
expect_history_end()
send_gdb('reverse-cont')
expect_history_end()

send_gdb('stepi')
send_gdb('reverse-stepi')
send_gdb('reverse-stepi')
expect_history_end()
send_gdb('reverse-cont')
expect_history_end()

ok()
