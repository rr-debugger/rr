from rrutil import *

send_gdb('break main\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')

send_gdb('watch -l var\n')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c\n')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

send_gdb('p atomic_printf("hello%s", "kitty")\n')
expect_gdb('hellokitty')

send_gdb('delete 2\n')

send_gdb('break pthread_join\n')
expect_gdb('Breakpoint 3')
send_gdb('c\n')
expect_gdb('Breakpoint 3')

send_gdb('p atomic_printf("hello%s", "kitty")\n')
expect_gdb('hellokitty')

send_gdb('c\n')
expect_gdb('EXIT-SUCCESS')

ok()
