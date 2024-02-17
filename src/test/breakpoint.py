from util import *

breakpoint = breakpoint_at_function('C')
cont()

expect_rr('calling C')
expect_breakpoint_stop(breakpoint)

backtrace()
expect_debugger('#0[^C]+C[^#]+#1[^B]+B[^#]+#2[^A]+A[^#]+#3.+main')

ok()
