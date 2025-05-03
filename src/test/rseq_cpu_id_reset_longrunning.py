from util import *
import re

send_gdb('break atomic_puts')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('break event_syscall')
expect_gdb('Breakpoint 2')
send_gdb('rc')
expect_gdb('Breakpoint 2')

send_gdb('c')
expect_gdb('Breakpoint 1')

ok()
