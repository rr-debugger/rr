from rrutil import *
import re

# Restart at the first debuggable event, which will be in a different
# process! We should stay focused on the child process, instead of
# trying to switch to that process. At least we shouldn't crash.
restart_replay(1)
expect_gdb('exited normally')

ok()
