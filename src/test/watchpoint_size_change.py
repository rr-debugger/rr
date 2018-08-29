from util import *

# Test conditional hardware breakpoint. For some reason
# gdb doesn't seem to use agent conditions for hardware
# watchpoint types other than conditional breakpoints.

send_gdb('break string_store')
expect_gdb('reakpoint 1')
send_gdb('c')
expect_gdb('reakpoint 1')
send_gdb('watch -l *(void**)(dest + 4095)')
expect_gdb('Hardware watchpoint 2')
send_gdb('c')
expect_gdb('Hardware watchpoint 2')

ok()
