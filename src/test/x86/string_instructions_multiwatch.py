from util import *
import re

send_gdb('b my_memmove')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb(re.compile(r'Buf is at ([^ \n]+)'))
buf = eval(last_match().group(1));
expect_gdb('Breakpoint 1')

send_gdb('watch -l *(char*)%d'%(buf + 14000))
expect_gdb('atchpoint 2')

send_gdb('c')
expect_gdb('atchpoint 2')

ok()
