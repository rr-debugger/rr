from rrutil import *
import re

send_gdb('when')
expect_gdb(re.compile(r'Current event: (\d+)'))
t = eval(last_match().group(1));
if t < 1 or t > 10000:
    failed('ERROR in first "when"')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks = eval(last_match().group(1));
if ticks != 0:
    failed('ERROR in first "when-ticks"')

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')

send_gdb('when')
expect_gdb(re.compile(r'Current event: (\d+)'))
t2 = eval(last_match().group(1));
if t2 < 1 or t2 > 10000:
    failed('ERROR in second "when"')
if t2 <= t:
    failed('ERROR ... "when" failed to advance')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks2 = eval(last_match().group(1));
if ticks2 < 0 or ticks2 > 100000:
    failed('ERROR in second "when-ticks"')
if ticks2 <= ticks:
    failed('ERROR ... "when-ticks" failed to advance')

# Ensure 'when' terminates a diversion
send_gdb('call strlen("abcd")')
send_gdb('when')
expect_gdb(re.compile(r'Current event not known \(diversion\?\)'))
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current event not known \(diversion\?\)'))
send_gdb('when-tid')
expect_gdb(re.compile(r'Current event not known \(diversion\?\)'))

ok()
