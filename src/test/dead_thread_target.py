from util import *
import re

send_gdb('b hit_barrier')
expect_gdb('Breakpoint 1')

send_gdb('b joined_threads')
expect_gdb('Breakpoint 2')

send_gdb('c')
expect_gdb('Breakpoint 1, hit_barrier')

send_gdb('info thr')
expect_gdb('2    Thread')

send_gdb('thr 2')
expect_gdb('Switching to thread 2')

send_gdb('c')
# TODO: with the gdb in fedora 19, if a thread dies while it's the
# resume target, then rr notifies gdb, but gdb doesn't ask for a new
# thread list.  This seems like a gdb bug, because we don't have any
# other way to notify gdb of thread death, and the same code works
# just fine in concurrent ubuntu and older versions.
#
# So we work around that problem by returning this special error code
# to the user.  Once gdb has made this mistake, the debugging session
# is "stuck" because won't let any other threads continue.  But at
# least this error code tells the user that they need to restart the
# session.
expect_gdb(re.compile(
    r'Breakpoint 2, joined_threads|Remote failure reply: E10'))

ok()
