from util import *

# Test conditional hardware breakpoint. For some reason
# gdb doesn't seem to use agent conditions for hardware
# watchpoint types other than conditional breakpoints.

send_gdb('hbreak main')
expect_gdb('reakpoint 1')
send_gdb('cond 1 var==0x1234')
send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
