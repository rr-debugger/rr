from util import *

send_gdb('b A')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_rr('calling A')
expect_gdb('Breakpoint 1, A')

send_gdb('n')
expect_rr('calling B')

send_gdb('s')
expect_gdb('B ()')

send_gdb('n')
expect_rr('calling C')

send_gdb('s')
expect_gdb('C ()')

send_gdb('bt')
expect_gdb('#0[^C]+C[^#]+#1[^B]+B[^#]+#2[^A]+A[^#]+#3[^m]+main')

ok()
