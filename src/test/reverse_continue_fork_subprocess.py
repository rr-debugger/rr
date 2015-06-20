from rrutil import *
import re

send_gdb('reverse-cont')
expect_gdb('SIGTRAP')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')
send_gdb('reverse-stepi')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')

send_gdb('stepi')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')
send_gdb('reverse-stepi')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')

send_gdb('stepi')
send_gdb('reverse-stepi')
send_gdb('reverse-stepi')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')

ok()
