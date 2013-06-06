from rrutil import *

send_gdb('b C\n')
expect_gdb('Breakpoint 1')

expect_gdb(r'\(gdb\)')
send_gdb('c\n')

expect_rr('calling C')

expect_gdb('Breakpoint 1, C')

send_gdb('bt\n')
expect_gdb('#0[^C]+C[^#]+#1[^B]+B[^#]+#2[^A]+A[^#]+#3[^m]+main')

ok()
