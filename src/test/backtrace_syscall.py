from rrutil import *

send_gdb('b __kernel_vsyscall\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('bt\n')
expect_gdb(r'#0 [^_]*__kernel_vsyscall \(\)')

ok()
