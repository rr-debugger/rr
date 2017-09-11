from util import *
import re

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('info proc mappings')
expect_gdb('\[vdso\]')

ok()
