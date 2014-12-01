from rrutil import *
import re

send_gdb('b breakpoint\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('fin\n')
expect_gdb(r'signal\(i, handle_sigrt\)')

send_gdb('n\n')
expect_gdb(r'raise\(i\)')

send_gdb('n\n')
expect_gdb('Program received signal SIG34')

send_gdb('stepi\n')
send_gdb('n\n')
expect_gdb(r'atomic_printf\("Caught signal')

ok()
