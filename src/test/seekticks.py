from util import *
import re

send_gdb('handle SIGKILL stop')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks = eval(last_match().group(1));
if ticks != 0:
    failed('ERROR in first "when-ticks"')

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('del 1')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks2 = eval(last_match().group(1));
if ticks2 < 0 or ticks2 > 1000000:
    failed('ERROR in second "when-ticks"')
if ticks2 <= ticks:
    failed('ERROR ... "when-ticks" failed to advance')

send_gdb('c')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks3 = eval(last_match().group(1));
if ticks3 < 0 or ticks3 > 1000000:
    failed('ERROR in second "when-ticks"')
if ticks3 <= ticks2:
    failed('ERROR ... "when-ticks" failed to advance')

send_gdb("seek-ticks %d" % ticks2)
expect_gdb("Program stopped.")
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks4 = eval(last_match().group(1));
if ticks4 != ticks2:
    failed('ERROR: Failed to seek back to ticks2')

send_gdb("seek-ticks %d" % ticks)
expect_gdb("Program stopped.")
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks5 = eval(last_match().group(1));
if ticks5 != ticks:
    failed('ERROR: Failed to seek back to ticks')

send_gdb("seek-ticks %d" % ticks2)
expect_gdb("Program stopped.")
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks6 = eval(last_match().group(1));
if ticks6 != ticks2:
    failed('ERROR: Failed to seek forwards to ticks2')

ok()
