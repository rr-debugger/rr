from rrutil import *

send_gdb('break main\n')
expect_gdb('Breakpoint 1')
send_gdb('c\n')
expect_gdb('Breakpoint 1')

# Test write watchpoint

send_gdb('p &var\n')
expect_gdb(r'\$1 = \(int \*\) ')

send_gdb('watch *$1\n')
expect_gdb('Hardware[()/a-z ]+watchpoint 2')

send_gdb('c\n')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

send_gdb('c\n')
expect_gdb('Old value = 42')
expect_gdb('New value = 1337')

restart_replay()
expect_gdb('Breakpoint 1')

# Test read-write watchpoint

send_gdb('delete 2\n')
send_gdb('awatch *$1\n')
expect_gdb('Hardware[()/a-z ]+watchpoint 3')

send_gdb('c\n')
expect_gdb('Old value = 0')
expect_gdb('New value = 42')

send_gdb('c\n')
expect_gdb('Old value = 42')
expect_gdb('New value = 1337')

send_gdb('c\n')
expect_gdb('Value = 1337')

restart_replay()
expect_gdb('Breakpoint 1')

# Test read watchpoint. x86 treats these as read-write.

send_gdb('delete 3\n')
send_gdb('rwatch *$1\n')
expect_gdb('Hardware[()/a-z ]+watchpoint 4')

send_gdb('c\n')
expect_gdb('Value = 42')

send_gdb('c\n')
expect_gdb('Value = 1337')

send_gdb('c\n')
expect_gdb('Value = 1337')

send_gdb('c\n')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
