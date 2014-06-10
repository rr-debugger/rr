import sys
import re
from rrutil import *

syscall_re = re.compile("`SYSCALL: getgid32' \\(state:1\\)")
sched_re = re.compile("`SCHED'")
eip_re = re.compile("eip:(0x[a-f0-9]+)")

sched_enabled = False
eip_enabled = False
eip = None
while True:
    line = sys.stdin.readline()
    if not line:
        break
    if syscall_re.search(line):
        sched_enabled = True
    if sched_enabled and sched_re.search(line):
        eip_enabled = True
    if eip_enabled:
        m = eip_re.search(line)
        if m:
            eip = m.group(1)
            break

if eip is None:
    failed('eip not found')

send_gdb('b *%s\n'%eip)
expect_gdb('Breakpoint 1')

send_gdb('c\n')
expect_gdb('Breakpoint 1')
expect_gdb('(gdb)')

send_gdb('p/x *(char*)$eip\n')
expect_gdb('0x([a-f0-9]+)')

if last_match().group(1) is 'cc':
    failed('saw breakpoint at current instruction')

ok()
