from util import *
import re

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('continue')
expect_gdb('Breakpoint 1')
send_gdb('s')
# Should have stepped into lib_exit_success where there's an atomic_puts
expect_gdb('atomic_puts')

ok()
