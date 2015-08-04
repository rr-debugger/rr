from rrutil import *

send_gdb('disass')
expect_gdb('function _start')

ok()
