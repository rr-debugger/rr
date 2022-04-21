from util import *
import re

send_gdb('reverse-stepi')
send_gdb('bt')
expect_gdb('_exit')

ok()
