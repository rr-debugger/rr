from util import *
import re

send_gdb('handle SIGKILL stop')
expect_gdb('SIGKILL')
send_gdb('continue')
expect_gdb('Killed')

send_gdb('break breakpoint')
expect_gdb('Breakpoint 1')
send_gdb('ignore 1 1000000')
expect_gdb('Will ignore')
send_gdb('reverse-continue')
expect_gdb('Program stopped')

ok()
