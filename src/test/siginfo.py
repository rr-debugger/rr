from util import *
import re

send_gdb('c')
expect_gdb('SIGUSR1')
send_gdb('print $_siginfo')
expect_gdb('si_signo = 10')
expect_gdb('si_code = -6')

ok()
