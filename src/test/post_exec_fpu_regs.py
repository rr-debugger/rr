from rrutil import *
import re

send_gdb('p $xmm0')
expect_gdb('v4_float = {0, 0, 0, 0}')
ok()
