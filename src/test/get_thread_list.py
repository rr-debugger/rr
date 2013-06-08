from rrutil import *
import re

NUM_THREADS = 10

send_gdb('b hit_barrier\n')
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1, hit_barrier')

send_gdb('info threads\n')
for i in xrange(NUM_THREADS + 1, 0, -1):
    expect_gdb(str(i) + r'\s+Thread')

ok()
