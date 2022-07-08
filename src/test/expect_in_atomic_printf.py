from util import *
import re

# Advance a bit, we may be in the jump stub.
# TODO: It would be nice to just teach gdb about this
for i in range(0,7):
    send_gdb('stepi')
    expect_gdb('(rr)')

send_gdb('bt')
expect_gdb('atomic_printf')

ok()
