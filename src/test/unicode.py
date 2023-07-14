from util import *
import re

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('checkpoint')
expect_gdb(re.compile(r'Checkpoint 1 at.*"𝕨ā≥3"'))

ok()
