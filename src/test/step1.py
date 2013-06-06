from rrutil import *

send_gdb('b A\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_rr('calling A')
expect_gdb('Breakpoint 1, A')

send_gdb('n\n')
expect_rr('calling B')

send_gdb('s\n')
expect_gdb('B ()')

send_gdb('n\n')
expect_rr('calling C')

send_gdb('s\n')
expect_gdb('C ()')

send_gdb('bt\n')
expect_gdb('#0[^C]+C[^#]+#1[^B]+B[^#]+#2[^A]+A[^#]+#3[^m]+main')

ok()
