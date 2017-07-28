from util import *
import re

send_gdb('handle SIGKILL stop')
send_gdb('c')
expect_gdb('received signal SIGKILL')

restart_replay()
expect_gdb('received signal SIGKILL')

send_gdb('c')
expect_gdb('exited normally')

ok()
