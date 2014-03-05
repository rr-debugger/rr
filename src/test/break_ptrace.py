from rrutil import *

send_gdb('c\n')
expect_rr('doing dummy PTRACE_ATTACH')
expect_gdb('Program received signal SIGTRAP')

send_gdb('bt\n')
expect_gdb('ptrace \(')

ok()
