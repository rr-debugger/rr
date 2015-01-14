from rrutil import *
import re

send_gdb('c\n')
index = expect_list([re.compile(r'exited normally'), re.compile(r'Program received signal SIGUSR1')])

if index == 1:
    send_gdb('c\n')
    expect_gdb('exited normally')

ok()
