from util import *
import re

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('p (int)open("diversion_print.out",0102,0600)')
expect_gdb(r'\$1 = (\d+)')
fd = last_match().group(1)
# This FD is confused with that during record. That's ok, just make sure
# operations on this during the diversion actually go to our file.

send_gdb(f'p (int)write({fd}, "DIVERSION-SUCCESS", 17)')
expect_gdb(r'\$2 = 17')

ok()
