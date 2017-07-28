import collections
import sys
import re
from util import *

send_gdb('checkpoint')
expect_gdb('Checkpoint 1 at')

send_gdb('n')
send_gdb('restart 1')
send_gdb('c')

expect_rr('EXIT-SUCCESS')

ok()
