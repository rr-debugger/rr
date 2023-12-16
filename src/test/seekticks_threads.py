from util import *
import re, os

send_gdb('restart 9')
expect_gdb(re.compile(r'Checkpoint 9 not found'))

def curr_thread():
    send_gdb('thread')
    expect_gdb(re.compile(r'\[Current thread is \d+ \(Thread (.*?)\)\]'))
    return last_match().group(1)

def expect_thread_tick(expected_thread, expected_tick):
    if curr_thread() != expected_thread:
        failed('ERROR: Incorrect thread: expected %s, got %s' % (expected_thread, curr_thread()))
    
    send_gdb('when-ticks')
    expect_gdb(re.compile(r'Current tick: (\d+)'))
    got_tick = int(last_match().group(1))
    if expected_tick != got_tick:
        failed('ERROR: Incorrect ticks: expected %d, got %d' % (expected_tick, got_tick))

def expect_stopped():
    expect_gdb(re.compile(r'(Thread \d+|Program) stopped'))
    


sched_matches = re.compile(r'global_time:(\d+).*ticks:(\d+)').findall(os.environ['SCHED_EVENTS'])
sched_events = [[int(y) for y in x] for x in sched_matches][:-2]
adj_count = 5
while True:
    if (len(sched_events) < adj_count):
        failed('ERROR: Adjacent SCHED events not found')
    last = sched_events[-adj_count:]
    if all([last[0][0]+i == last[i][0] for i in range(adj_count)]):
        break
    sched_events.pop()

sched_events = sched_events[-adj_count:]
[event_A, tick_A] = sched_events[1]
[event_B, tick_B] = sched_events[2]
[event_C, tick_C] = sched_events[3]
[event_D, tick_D] = sched_events[4]

tests = [
    # event; expected tick at event; another tick on the same thread
    [event_B, tick_A, tick_C],
    [event_C, tick_B, tick_D]]

threads = set()
is_first = True
for [start_event, initial_tick, other_tick] in tests:
    center_tick = (initial_tick + other_tick) // 2
    
    send_gdb('run %d' % start_event)
    if not is_first:
        expect_gdb('from the beginning')
        send_gdb('y')
    is_first = False
    expect_stopped()
    
    thread = curr_thread()
    threads.add(thread)
    
    expect_thread_tick(thread, initial_tick)

    send_gdb('seek-ticks %d' % center_tick)
    expect_stopped()
    expect_thread_tick(thread, center_tick)

    send_gdb('seek-ticks %d' % center_tick)
    expect_stopped()
    expect_thread_tick(thread, center_tick)

    ticks = center_tick + 1
    send_gdb('seek-ticks %d' % ticks)
    expect_stopped()
    expect_thread_tick(thread, ticks)

    ticks = center_tick - 1
    send_gdb('seek-ticks %d' % ticks)
    expect_stopped()
    expect_thread_tick(thread, ticks)

    send_gdb('seek-ticks %d' % initial_tick)
    expect_stopped()
    expect_thread_tick(thread, initial_tick)

    send_gdb('seek-ticks %d' % other_tick)
    expect_stopped()
    expect_thread_tick(thread, other_tick)
    
    send_gdb('info threads')
    expect_gdb(r'\d\s*Thread')
    expect_gdb(r'\d\s*Thread')
    
if len(threads) != 2:
    failed('ERROR: Tested events had the same thread')

ok()
