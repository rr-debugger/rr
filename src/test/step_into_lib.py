from util import *
import re

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('continue')
expect_gdb('Breakpoint 1')
expect_gdb(re.compile(r'\s([a-z_]+)\('))
if last_match().group(1) == 'main':
    send_gdb('s')
    expect_gdb('lib_exit_success')

send_gdb('s')
# Should have stepped into lib_exit_success where there's an atomic_puts
expect_gdb('atomic_puts')

ok()
