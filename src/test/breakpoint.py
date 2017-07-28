from util import *

send_gdb('b C')
expect_gdb('Breakpoint 1')

send_gdb('c')

expect_rr('calling C')

expect_gdb('Breakpoint 1, C')

send_gdb('bt')
expect_gdb('#0[^C]+C[^#]+#1[^B]+B[^#]+#2[^A]+A[^#]+#3[^m]+main')

ok()
