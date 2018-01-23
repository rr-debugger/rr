from util import *
import re

send_gdb('hbreak *syscall_instruction')
expect_gdb('breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('stepi')
send_gdb('print $pc == syscall_instruction + 2')
expect_gdb('= 1')
send_gdb('reverse-stepi')
send_gdb('print $pc == syscall_instruction')
expect_gdb('= 1')

ok()
