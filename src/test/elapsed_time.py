import time

from util import *
import re

# Get monotonic timer value from right now
monotonic_start = time.monotonic()

send_gdb("absolute-time")
expect_gdb(re.compile(r'(?<=Absolute Time \(s\): )[0-9.]+'))
absolute_time_start = float(last_match().group(0))

if absolute_time_start > monotonic_start:
    failed("ERROR ... The reported monotonic time at the start was after the test script started")
if absolute_time_start < monotonic_start - 300:
    failed("ERROR ... The reported monotonic time at the start was over five minutes before the test script started")

send_gdb('elapsed-time')

expect_gdb(re.compile(r'(?<=Elapsed Time \(s\): )[0-9.]+'))
elapsed_start = float(last_match().group(0))

# Test that the elapsed-time GDB command returns a time >= 1.0 at a breakpoint
# after sleep(1);


send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
send_gdb('elapsed-time')

expect_gdb(re.compile(r'(?<=Elapsed Time \(s\): )[0-9.]+'))
elapsed_time = float(last_match().group(0))
sleep_time = 1.0
if elapsed_time < sleep_time:
    failed('ERROR ... The reported elapsed time after sleeping for ' +
           f'{sleep_time} (s) was {elapsed_time}')

send_gdb("absolute-time")
expect_gdb(re.compile(r'(?<=Absolute Time \(s\): )[0-9.]+'))
absolute_time_end = float(last_match().group(0))

sleep_time_absolute = absolute_time_end - absolute_time_start
sleep_time_relative = elapsed_time - elapsed_start

if abs(sleep_time_absolute - sleep_time_relative) > 0.0001:
    failed(f"ERROR ... The sleep time reported by absolute-time vs elapsed-time was too far apart (should be as equal as double allows): {sleep_time_absolute} - {sleep_time_relative} = {sleep_time_absolute - sleep_time_relative}" )

ok()
