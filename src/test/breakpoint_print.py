from util import *
import re

bp = breakpoint_at_function('main')
set_breakpoint_commands(bp, ['print 123 + 456'])
cont()
expect_debugger('579')

ok()
