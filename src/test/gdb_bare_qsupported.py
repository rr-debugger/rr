from util import *

# qSupported with no client feature list is valid and must not crash rr.
send_gdb('maintenance packet qSupported')
expect_gdb('PacketSize=')
send_gdb('maintenance packet qSupported:')
expect_gdb('PacketSize=')

ok()
