import re
from util import *

send_gdb('b rdtsc')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1, rdtsc')

send_gdb('disass')
expect_gdb(re.compile(r'=> ([0-9a-fx]+) <\+[0-9]+>:\trdtsc'))

addr = last_match().group(1)

send_gdb('stepi')
send_gdb('disass')
expect_gdb(re.compile(r'=> ([0-9a-fx]+) '))

addr2 = last_match().group(1)

if eval(addr) + 2 != eval(addr2):
  failed("stepi from rdtsc at %s ended at incorrect %s" % (addr, addr2));

ok()
