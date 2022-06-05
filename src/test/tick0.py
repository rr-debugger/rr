from util import *
import re

send_gdb('handle SIGKILL stop')

send_gdb('when')
expect_gdb(re.compile(r'Current event: (\d+)'))
event = eval(last_match().group(1));

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks = eval(last_match().group(1));
if ticks != 0:
    failed('ERROR in first "when-ticks"')

send_gdb('c')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks2 = eval(last_match().group(1));
if ticks2 < 99999:
    failed('ERROR in second "when-ticks"')

send_gdb("seek-ticks %d" % ticks)
expect_gdb("Program stopped.")
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
ticks3 = eval(last_match().group(1));
if ticks3 != ticks:
    failed('ERROR: Failed to seek back to ticks')

send_gdb('when')
expect_gdb(re.compile(r'Current event: (\d+)'))
event2 = eval(last_match().group(1));
if event2 != event:
    failed('ERROR: Failed to seek back to ticks')

ok()
