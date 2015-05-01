from rrutil import *
import re

send_gdb('when')
expect_gdb(re.compile(r'= (\d+)'))
t = eval(last_match().group(1));
if t < 1 or t > 10000:
    failed('ERROR in first "when"')

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')

send_gdb('when')
expect_gdb(re.compile(r'= (\d+)'))
t2 = eval(last_match().group(1));
if t2 < 1 or t2 > 10000:
    failed('ERROR in second "when"')
if t2 <= t:
    failed('ERROR ... "when" failed to advance')

ok()
