from rrutil import *
import re

send_gdb('reverse-cont')
expect_gdb('SIGTRAP')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')
send_gdb('reverse-stepi')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')
send_gdb('reverse-stepi')
send_gdb('reverse-cont')
expect_gdb('SIGTRAP')

ok()
