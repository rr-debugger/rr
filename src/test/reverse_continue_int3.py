from util import *

send_gdb('c')
expect_gdb('SIGTRAP')

send_gdb('rc')
expect_gdb('SIGTRAP')

send_gdb('rc')
expect_gdb('stopped')

ok()
