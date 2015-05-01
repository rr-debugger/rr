from rrutil import *

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, breakpoint')

send_gdb('call mutate_var()')
expect_gdb('var is 22')

send_gdb('call print_nums()')
expect_gdb('1 2 3 4 5')

send_gdb('call alloc_and_print()')
expect_gdb('Hello 22')

send_gdb('call make_unhandled_syscall()')
expect_gdb('return from kill: -1')

send_gdb('call print_time()')
expect_gdb(r'now is \d+(\.\d+(e\+\d\d)?)? sec')

send_gdb('c')
expect_rr('var is -42')

ok()
