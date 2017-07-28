from util import *
import re

send_gdb('handle SIGKILL stop')

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('b __before_poll_syscall_breakpoint')
expect_gdb('Breakpoint 2')
send_gdb('c')
index = expect_list([re.compile(r'Breakpoint 2'), re.compile(r'SIGKILL')])
if index == 0:
  # This is testing that we can reverse-step without crashing rr.
  send_gdb('reverse-stepi')
  send_gdb('c')
  expect_gdb('Breakpoint 2')

ok()
