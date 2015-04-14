import collections
import sys
import re
from rrutil import *

send_gdb('checkpoint\n')
expect_gdb('= 1')

send_gdb('n\n')
send_gdb('restart 1\n')

expect_rr('EXIT-SUCCESS')

ok()
