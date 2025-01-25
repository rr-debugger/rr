from util import *
import re

send_gdb('handle SIGKILL stop')

send_gdb('c')
expect_gdb('Program received signal SIGKILL')

send_gdb('rc')
expect_gdb([f'({history_end_regex()})', '(child)'])

assert 'child' not in last_match().group(1)

send_gdb('c')
expect_gdb('Program received signal SIGKILL')

ok()
