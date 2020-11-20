from util import *
import re, sys

send_gdb('b breakpoint')
expect_gdb('Breakpoint 1')

send_gdb('c')
expect_gdb('Breakpoint 1')

send_gdb('p hardware_breakpoint()')
expect_gdb('Program received signal SIGTRAP')
