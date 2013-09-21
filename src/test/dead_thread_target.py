from rrutil import *

send_gdb('b hit_barrier\n')
expect_gdb('Breakpoint 1')

send_gdb('b joined_threads\n')
expect_gdb('Breakpoint 2')

send_gdb('c\n')
expect_gdb('Breakpoint 1, hit_barrier')

send_gdb('info thr\n')
expect_gdb('2    Thread')

send_gdb('thr 2\n')
expect_gdb('Switching to thread 2')

send_gdb('c\n')
expect_gdb('Breakpoint 2, joined_threads')

ok()
