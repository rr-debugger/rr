from util import *
import re

send_custom_command('when')
expect_debugger(re.compile(r'Completed event: (\d+)'))
t = int(last_match().group(1))
if t < 1 or t > 10000:
    failed('ERROR in first "when"')

send_custom_command('when-ticks')
expect_debugger(re.compile(r'Current tick: (\d+)'))
ticks = int(last_match().group(1))
if ticks != 0:
    failed('ERROR in first "when-ticks"')

send_custom_command('when-tid')
expect_debugger(re.compile(r'Current tid: (\d+)'))
tid = int(last_match().group(1))

bp = breakpoint_at_function('main')
cont()
expect_breakpoint_stop(bp)

send_custom_command('when')
expect_debugger(re.compile(r'Completed event: (\d+)'))
t2 = int(last_match().group(1))
if t2 < 1 or t2 > 10000:
    failed('ERROR in second "when"')
if t2 <= t:
    failed('ERROR ... "when" failed to advance')

send_custom_command('when-ticks')
expect_debugger(re.compile(r'Current tick: (\d+)'))
ticks2 = int(last_match().group(1))
if ticks2 < 0 or ticks2 > 1000000:
    failed('ERROR in second "when-ticks"')
if ticks2 <= ticks:
    failed('ERROR ... "when-ticks" failed to advance')

send_custom_command('when-tid')
expect_debugger(re.compile(r'Current tid: (\d+)'))
tid2 = int(last_match().group(1))
if tid2 != tid:
    failed('ERROR ... tid changed')

# Ensure 'when' terminates a diversion
expect_expression('(int)strlen("abcd")', 4)
send_custom_command('when')
expect_debugger(re.compile(r'Completed event: (\d+)'))
t3 = int(last_match().group(1))
if t3 != t2:
    failed('ERROR ... diversion changed event')

expect_expression('(int)strlen("abcd")', 4)
send_custom_command('when-ticks')
expect_debugger(re.compile(r'Current tick: (\d+)'))
ticks3 = int(last_match().group(1))
if ticks3 != ticks2:
    failed('ERROR ... diversion changed ticks')

expect_expression('(int)strlen("abcd")', 4)
send_custom_command('when-tid')
expect_debugger(re.compile(r'Current tid: (\d+)'))
tid3 = int(last_match().group(1))
if tid3 != tid2:
    failed('ERROR ... diversion changed tid')

ok()
