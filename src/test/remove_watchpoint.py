from util import *

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('watch -l var')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

send_gdb('p atomic_printf("hello%s", "kitty")')
expect_gdb('hellokitty')

send_gdb('delete 2')

send_gdb('break pthread_join')
expect_gdb('Breakpoint 3')
send_gdb('c')
expect_gdb('Breakpoint 3')

send_gdb('p atomic_printf("hello%s", "kitty")')
expect_gdb('hellokitty')

send_gdb('c')
expect_gdb('EXIT-SUCCESS')

ok()
