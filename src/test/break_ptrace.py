from rrutil import *

send_gdb('c\n')
expect_rr('doing dummy PTRACE_ATTACH')
expect_gdb('exited')

ok()
