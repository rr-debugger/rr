from util import *
import re

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('fin')
index = expect_list([re.compile(r'signal\(i, handle_sigrt\)'), re.compile('breakpoint')])
if index == 1:
    send_gdb('n')
    expect_gdb(r'signal\(i, handle_sigrt\)')

send_gdb('n')
expect_gdb(r'raise\(i\)')

send_gdb('n')
expect_gdb('Program received signal SIG34')

send_gdb('stepi')
send_gdb('n')
expect_gdb(r'atomic_printf\("Caught signal')

ok()
