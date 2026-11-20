from util import *

send_gdb('c')
expect_rr('EXIT-SUCCESS')
expect_gdb('exited normally')

ok()
