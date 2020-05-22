from util import *
import re

send_gdb('break *cpuid_instruction_label')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
expect_gdb('(rr)')

send_gdb('p $pc')
expect_gdb(re.compile(r'(0x[a-f0-9]+)'))
pc = eval(last_match().group(1));
expect_gdb('(rr)')
send_gdb('stepi')
expect_gdb('(rr)')

send_gdb('p $pc')
expect_gdb(re.compile(r'(0x[a-f0-9]+)'))
pc2 = eval(last_match().group(1));
if pc2 - pc != 2:
    failed('Expected 0x%x after singlestep, got 0x%x'%(pc + 2, pc2))

send_gdb('c')
expect_gdb('EXIT-SUCCESS')

ok()
