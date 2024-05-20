from util import *
import re

send_gdb('break do_thread')
expect_gdb('Breakpoint 1')
send_gdb('continue')
expect_gdb('Breakpoint 1')

send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
thread_ticks = int(last_match().group(1));
send_gdb('when-tid')
expect_gdb(re.compile(r'Current tid: (\d+)'))
thread_tid = int(last_match().group(1));

send_gdb('info threads')
expect_gdb('do_thread')
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
thread_ticks2 = int(last_match().group(1));
assert thread_ticks == thread_ticks2
send_gdb('when-tid')
expect_gdb(re.compile(r'Current tid: (\d+)'))
thread_tid2 = int(last_match().group(1));
assert thread_tid == thread_tid2

send_gdb('thread 1')
expect_gdb('Switching')
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
main_ticks = int(last_match().group(1));
send_gdb('when-tid')
expect_gdb(re.compile(r'Current tid: (\d+)'))
main_tid = int(last_match().group(1));

send_gdb('info threads')
expect_gdb('do_thread')
send_gdb('when-ticks')
expect_gdb(re.compile(r'Current tick: (\d+)'))
main_ticks2 = int(last_match().group(1));
assert main_ticks == main_ticks2
send_gdb('when-tid')
expect_gdb(re.compile(r'Current tid: (\d+)'))
main_tid2 = int(last_match().group(1));
assert main_tid == main_tid2

ok()
