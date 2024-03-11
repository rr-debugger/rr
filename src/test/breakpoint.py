from util import *

breakpoint_at('C', 1)
cont()

expect_rr('calling C')
expect_breakpoint_stop(1)

backtrace()
expect_debugger('#0[^C]+C[^#]+#1[^B]+B[^#]+#2[^A]+A[^#]+#3.+main')

ok()
