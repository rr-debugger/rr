from rrutil import *
import re

send_gdb('p *(int*)0x123\n')
expect_gdb('Cannot access memory')

ok()
