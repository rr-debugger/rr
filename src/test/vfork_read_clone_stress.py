from util import *
import re

send_gdb('handle SIGKILL stop')

send_gdb('c')
expect_gdb('SIGKILL')

send_gdb('rc')
expect_gdb('Program stopped.')

send_gdb('c')
ok()
