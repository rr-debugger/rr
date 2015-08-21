import collections
import sys
import re
from rrutil import *

send_gdb('checkpoint')
expect_gdb('= 1')

send_gdb('n')
send_gdb('restart 1')
send_gdb('c')

expect_rr('EXIT-SUCCESS')

ok()
