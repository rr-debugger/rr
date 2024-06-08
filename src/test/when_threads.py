from util import *
import re

bp = breakpoint_at_function('do_thread')
cont()
expect_breakpoint_stop(bp)

send_custom_command('when-ticks')
expect_debugger(re.compile(r'Current tick: (\d+)'))
thread_ticks = int(last_match().group(1))
send_custom_command('when-tid')
expect_debugger(re.compile(r'Current tid: (\d+)'))
thread_tid = int(last_match().group(1))

expect_threads(2, 2)
send_custom_command('when-ticks')
expect_debugger(re.compile(r'Current tick: (\d+)'))
thread_ticks2 = int(last_match().group(1))
assert thread_ticks == thread_ticks2
send_custom_command('when-tid')
expect_debugger(re.compile(r'Current tid: (\d+)'))
thread_tid2 = int(last_match().group(1))
assert thread_tid == thread_tid2

select_thread(1)
send_custom_command('when-ticks')
expect_debugger(re.compile(r'Current tick: (\d+)'))
main_ticks = int(last_match().group(1))
send_custom_command('when-tid')
expect_debugger(re.compile(r'Current tid: (\d+)'))
main_tid = int(last_match().group(1))

expect_threads(2, 1)
send_custom_command('when-ticks')
expect_debugger(re.compile(r'Current tick: (\d+)'))
main_ticks2 = int(last_match().group(1))
assert main_ticks == main_ticks2
send_custom_command('when-tid')
expect_debugger(re.compile(r'Current tid: (\d+)'))
main_tid2 = int(last_match().group(1))
assert main_tid == main_tid2

ok()
