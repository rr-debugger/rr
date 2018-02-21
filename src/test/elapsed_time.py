from util import *
import re

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
    failed("ERROR ... The reported elapsed time after sleeping for " +
           "{sleep_time} (s) was {elapsed_time}".format(
               sleep_time=sleep_time, elapsed_time=elapsed_time))

ok()
