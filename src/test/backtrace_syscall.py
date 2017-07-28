from util import *

send_gdb('b __kernel_vsyscall')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('bt')
expect_gdb(r'#0 [^_]*__kernel_vsyscall \(\)')

ok()
