from util import *
import re

send_gdb('bt')
expect_gdb('atomic_printf')

ok()
