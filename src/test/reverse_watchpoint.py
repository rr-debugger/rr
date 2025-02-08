from util import *

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('continue')
expect_gdb('Breakpoint 1')
send_gdb('delete 1')
send_gdb('watch -l var')
expect_gdb('Hardware watchpoint 2')
send_gdb('break atomic_puts')
expect_gdb('Breakpoint 3')

send_gdb('c')
expect_gdb('Hardware watchpoint 2')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

send_gdb('c')
expect_gdb('Hardware watchpoint 2')
expect_gdb('Old value = 42')
expect_gdb('New value = 1337')

send_gdb('c')
expect_gdb('Breakpoint 3')

send_gdb('reverse-cont')
expect_gdb('Hardware watchpoint 2')
expect_gdb('Old value = 1337')
expect_gdb('New value = 42')

send_gdb('reverse-cont')
expect_gdb('Hardware watchpoint 2')
expect_gdb('Old value = 42')
expect_gdb('New value = 0')

send_gdb('reverse-cont')
expect_history_end()

ok()
