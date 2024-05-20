from util import *
import re

send_gdb('handle SIGKILL stop')

def get_when():
    send_gdb('when')
    expect_gdb(re.compile(r'Completed event: (\d+)'))
    event = int(last_match().group(1))

    send_gdb('when-ticks')
    expect_gdb(re.compile(r'Current tick: (\d+)'))
    ticks = int(last_match().group(1))
    return (event, ticks)

(event_start, ticks_start) = get_when()
if ticks_start != 0:
    failed('ERROR: Wrong initial ticks')

send_gdb('c')

(event_end, ticks_end) = get_when()
if ticks_end < 99999:
    failed('End ticks too low')

send_gdb("seek-ticks %d" % ticks_start)
expect_gdb("Program stopped.")
(event_exp, ticks_from_end) = get_when()
if ticks_from_end != ticks_start:
    failed('ERROR: Failed to seek back to tick 0 from end')

# test at some starting events
for event in range(event_start-1, min(event_start+5, event_end-1)):
    send_gdb('run %d' % event)
    expect_gdb('from the beginning')
    send_gdb('y')
    expect_gdb(re.compile(r'(Thread \d+|Program) stopped'))
    
    
    send_gdb("seek-ticks %d" % ticks_start)
    expect_gdb("Program stopped.")
    
    (event, ticks) = get_when()
    if ticks != 0:
        failed('ERROR: Failed to seek back to tick 0 from run')
    if event != event_exp:
        failed('ERROR: Inconsistent result events from seek-ticks 0')

ok()
