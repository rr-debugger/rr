from util import *

send_gdb('break start_test')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('break _syscall_hook_trampoline')
expect_gdb('Breakpoint 2')
send_gdb('c')
expect_gdb('Breakpoint 2')

send_gdb('fin')
send_gdb('fin')
send_gdb('fin')

# Verify we didn't run too far

send_gdb('b breakpoint')
expect_gdb('Breakpoint 3')

send_gdb('c')
expect_gdb('Breakpoint 3')

ok()
