from util import *
import re

send_gdb('reverse-cont')
expect_gdb('stopped')
send_gdb('reverse-cont')
expect_gdb('stopped')
send_gdb('reverse-stepi')
expect_gdb('stopped')
send_gdb('reverse-cont')
expect_gdb('stopped')

send_gdb('stepi')
send_gdb('reverse-cont')
expect_gdb('stopped')
send_gdb('reverse-cont')
expect_gdb('stopped')
send_gdb('reverse-stepi')
expect_gdb('stopped')
send_gdb('reverse-cont')
expect_gdb('stopped')

send_gdb('stepi')
send_gdb('reverse-stepi')
send_gdb('reverse-stepi')
expect_gdb('stopped')
send_gdb('reverse-cont')
expect_gdb('stopped')

ok()
