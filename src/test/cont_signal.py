from util import *
import re

send_gdb('c')
index = expect_list([re.compile(r'exited normally'), re.compile(r'Program received signal SIGUSR1')])

if index == 1:
    send_gdb('c')
    expect_gdb('exited normally')

ok()
