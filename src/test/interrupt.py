from util import *

# XXX this test is racy, because we don't have a way to halt replay
# until some condition is satisfied.  Maybe we should add that.
send_gdb('c')
expect_rr('spinning')
interrupt_gdb()

ok()
