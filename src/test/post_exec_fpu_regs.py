from rrutil import *
import re

send_gdb('p $xmm0')
expect_gdb('uint128 = 0}')
ok()
