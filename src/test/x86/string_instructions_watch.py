from util import *
import re

send_gdb('b string_store')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('p buf')
expect_gdb(re.compile(r'= ([^ ]+)'))
buf = eval(last_match().group(1));

send_gdb('watch -l *(uint16_t*)%d'%(buf + 13))
expect_gdb('atchpoint 2')

send_gdb('watch -l *(char*)-1')
expect_gdb('atchpoint 3')

send_gdb('c')
expect_gdb('atchpoint 2')

send_gdb('p buf[13]')
expect_gdb('= 97')
send_gdb('p buf[14]')
expect_gdb('= 0')

ok()
