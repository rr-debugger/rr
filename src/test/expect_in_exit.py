from util import *
import re

# Step out of the extended syscall jump patch.
for i in range(0,3):
    send_gdb('reverse-stepi')
    expect_gdb('(rr)')

send_gdb('bt')
expect_gdb('_exit')

ok()
