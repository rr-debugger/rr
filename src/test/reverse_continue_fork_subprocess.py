from util import *
import re

send_gdb('reverse-cont')
expect_gdb('No more reverse-execution history')
send_gdb('reverse-cont')
expect_gdb('No more reverse-execution history')
send_gdb('reverse-stepi')
expect_gdb('No more reverse-execution history')
send_gdb('reverse-cont')
expect_gdb('No more reverse-execution history')

send_gdb('stepi')
send_gdb('reverse-cont')
expect_gdb('No more reverse-execution history')
send_gdb('reverse-cont')
expect_gdb('No more reverse-execution history')
send_gdb('reverse-stepi')
expect_gdb('No more reverse-execution history')
send_gdb('reverse-cont')
expect_gdb('No more reverse-execution history')

send_gdb('stepi')
send_gdb('reverse-stepi')
send_gdb('reverse-stepi')
expect_gdb('No more reverse-execution history')
send_gdb('reverse-cont')
expect_gdb('No more reverse-execution history')

ok()
