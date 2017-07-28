from util import *
import re

send_gdb('b my_memmove')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('p src')
expect_gdb(re.compile(r'= ([^ ]+)'))
buf = eval(last_match().group(1));

send_gdb('watch -l *(char*)%d'%(buf + 10000))
expect_gdb('atchpoint 2')

send_gdb('c')
expect_gdb('atchpoint 2')

ok()
