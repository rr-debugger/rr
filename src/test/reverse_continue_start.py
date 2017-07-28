from util import *
import re

send_gdb('reverse-cont')
expect_gdb('stopped')
send_gdb('reverse-cont')
expect_gdb('stopped')
send_gdb('reverse-stepi')
expect_gdb('stopped')
send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('reverse-cont')
expect_gdb('stopped')
send_gdb('reverse-stepi')
expect_gdb('stopped')
send_gdb('reverse-cont')
expect_gdb('stopped')

ok()
