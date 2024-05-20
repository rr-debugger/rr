from util import *
import re

send_gdb('handle SIGKILL stop')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks = int(last_match().group(1))
if ticks != 0:
    failed('ERROR in first "when-ticks"')

send_gdb('b main')
expect_gdb('Breakpoint 1')
send_gdb('c')
expect_gdb('Breakpoint 1')
send_gdb('del 1')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks2 = int(last_match().group(1))
if ticks2 < 0 or ticks2 > 1000000:
    failed('ERROR in second "when-ticks"')
if ticks2 <= ticks:
    failed('ERROR ... "when-ticks" failed to advance')

send_gdb('c')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks3 = int(last_match().group(1))
if ticks3 < 0 or ticks3 > 1000000:
    failed('ERROR in second "when-ticks"')
if ticks3 <= ticks2:
    failed('ERROR ... "when-ticks" failed to advance')

send_gdb("seek-ticks %d" % ticks2)
expect_gdb("Program stopped.")
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks4 = int(last_match().group(1))
if ticks4 != ticks2:
    failed('ERROR: Failed to seek back to ticks2')

send_gdb("seek-ticks %d" % ticks)
expect_gdb("Program stopped.")
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks5 = int(last_match().group(1))
if ticks5 != ticks:
    failed('ERROR: Failed to seek back to ticks')

send_gdb("seek-ticks %d" % ticks2)
expect_gdb("Program stopped.")
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks6 = int(last_match().group(1))
if ticks6 != ticks2:
    failed('ERROR: Failed to seek forwards to ticks2')

if ticks2 < 4:
    failed('ERROR: ticks2 too small to test nearby ticks')

tests = [ticks2, ticks2, ticks2-2, 1, 1, 0, 0, 2, 0, 2, ticks2-2, ticks2-1, ticks2-2, ticks2]

for i in range(len(tests)):
    ticks7 = tests[i]
    send_gdb("seek-ticks %d" % ticks7)
    expect_gdb("Program stopped.")
    send_gdb('when-ticks')
    expect_gdb(re.compile(r'Current tick: (\d+)'))
    ticks8 = int(last_match().group(1))
    if ticks8 != ticks7:
        failed("ERROR: seek-ticks didn't go to correct tick on test %d" % i)

send_gdb('seek-ticks 2000000000')
expect_gdb('No event found matching specified ticks target')
send_gdb('info threads')
# don't expect anything specific from 'info threads', but make sure gdb at least functions
send_gdb('p 123456789+1')
expect_gdb('123456790')
ok()
