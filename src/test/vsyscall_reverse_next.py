import datetime
from util import *

send_gdb('break vsyscall_reverse_next.c:6')
expect_gdb('Breakpoint 1')
send_gdb('print "' + datetime.datetime.now().strftime("%Y-%m-%d, %H:%M:%S.%f") + '"')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('print "' + datetime.datetime.now().strftime("%Y-%m-%d, %H:%M:%S.%f") + '"')
send_gdb('disable 1')

send_gdb('n')
expect_gdb('atomic_puts')
send_gdb('print "' + datetime.datetime.now().strftime("%Y-%m-%d, %H:%M:%S.%f") + '"')

send_gdb('reverse-next')
expect_gdb('time')
send_gdb('print "' + datetime.datetime.now().strftime("%Y-%m-%d, %H:%M:%S.%f") + '"')

ok()
