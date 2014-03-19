from rrutil import *

send_gdb('b breakpoint\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('f 1\n')
expect_gdb('#1')

send_gdb('p &var\n')
expect_gdb(r'\$1 = \(int \*\) ')

send_gdb('watch *$1\n')
expect_gdb('Hardware watchpoint 2')

# TODO: since rr doesn't actually set watchpoints yet, we just ensure
# that we can clear the watchpoint and continue debugging.
send_gdb('c\n')
expect_rr('rr: Warning: attempt to set unhandled watchpoint type.')
send_gdb('del 2\n')

send_gdb('c\n')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
