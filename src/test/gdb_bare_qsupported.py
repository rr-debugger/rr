from util import *

# qSupported with no client feature list is valid and must not crash rr.
send_gdb('maintenance packet qSupported')
expect_gdb('PacketSize=')
send_gdb('maintenance packet qSupported:')
expect_gdb('PacketSize=')

send_gdb('break main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')

ok()
