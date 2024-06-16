from util import *

send_gdb('delete checkpoint')
expect_gdb('requires an argument')

send_gdb('delete checkpoint x')
expect_gdb('Invalid checkpoint number')

send_gdb('delete checkpoint 0x1')
expect_gdb('Invalid checkpoint number')

send_gdb('delete checkpoint -1')
expect_gdb('No checkpoint number')

send_gdb('delete checkpoint 0')
expect_gdb('No checkpoint number')

send_gdb('delete checkpoint 99999999999999999999999999999999999999999')
expect_gdb('No checkpoint number')

ok()
