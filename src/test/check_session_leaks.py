from util import *
import re

send_gdb('b atomic_puts')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

for i in range(1,100):
    send_gdb('checkpoint')
    expect_gdb('Checkpoint %d '%i)
    send_gdb('stepi')
    send_gdb('restart %d'%i)
    expect_gdb('stopped')
    send_gdb('delete checkpoint %d'%i)
    send_gdb('stepi')
    send_gdb('stepi')

ok()
