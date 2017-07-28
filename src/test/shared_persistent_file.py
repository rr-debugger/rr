from util import *
import re

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('check')
expect_gdb('Checkpoint 1 at')
send_gdb('c')
expect_gdb('xited normally')
send_gdb('restart 1')
expect_gdb('stopped')
send_gdb('c')
expect_gdb('xited normally')

ok()
