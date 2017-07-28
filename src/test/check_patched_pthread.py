from util import *
import re

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('p ((int*)&__elision_aconf)[2]')
expect_gdb(re.compile(r'= 0|No symbol'))
send_gdb('p/x *(char*)elision_init')
expect_gdb(re.compile(r'= 0xc3|No symbol'))

ok()
