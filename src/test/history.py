from rrutil import *
import re

def get_rip():
    send_gdb('print $rip')
    expect_gdb(re.compile(r'(.*) \(void \(\*\)\(\)\) (0[xX][0-9a-fA-F]+) (.*)'))
    return eval(last_match().group(2));

send_gdb('b breakpointA')
expect_gdb('Breakpoint 1')
send_gdb('c')

expect_gdb('i=0')
send_gdb('c')
expect_gdb('i=1')
send_gdb('c')
expect_gdb('i=2')
send_gdb('c')
expect_gdb('i=3')
send_gdb('c')
expect_gdb('i=4')

send_gdb('forward')
expect_gdb("Can't go forward. No more history entries.")

send_gdb('back')
expect_gdb('i=3')
send_gdb('back')
expect_gdb('i=2')
send_gdb('back')
expect_gdb('i=1')

# A diversion should not interfere with the history
send_gdb('call strlen("abcd")')

send_gdb('back')
expect_gdb('i=0')

# Clear the forward stack by pushing a new entry
send_gdb('c')
expect_gdb('i=1')
send_gdb('forward')
expect_gdb("Can't go forward. No more history entries.")

send_gdb('back')
expect_gdb('i=0')

# si/back should restore the current state
old_rip = get_rip()
send_gdb('si')
send_gdb('back')
new_rip = get_rip()
if old_rip != new_rip:
    failed('ERROR back did not restore IP')

# TODO Support 'back' after the program has terminated
# Run to end of the program and restore the state
# User story: Miss a breakpoint and accidentaly terminate the program
# send_gdb('delete 1')
# send_gdb('continue')
# expect_gdb('EXIT-SUCCESS')
# send_gdb('back')
# if old_rip != new_rip:
#     failed('ERROR back did not restore IP')

# Finish execution
send_gdb('continue')
expect_gdb('EXIT-SUCCESS')
ok()
