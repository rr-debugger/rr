from util import *

# gdb sends an interrupt for "interrupt" even when it knows that the process
# is stopped, so rr gets it while the process is stopped, as when a debugger
# interrupts a process that has just stopped. rr must not reply to it: the
# debugger would take the reply as the reply to its next request. The
# interrupt takes effect when the process is next resumed: it stops again
# right away.

def get_pc():
    send_gdb('p/x $pc')
    expect_gdb(r'= (0x[0-9a-f]+)')
    return last_match().group(1)

def interrupt():
    send_gdb('interrupt')
    send_gdb('maint packet qC')
    expect_gdb(r'received: "(\w)|Remote communication error')
    if last_match().group(1) != 'Q':
        failed('rr replied to an interrupt while the process was stopped')

def expect_stop_at(pc, stop):
    expect_gdb(r'Program stopped|Program received signal \w+|Breakpoint \d|exited')
    if last_match().group(0) != stop:
        failed(f'expected "{stop}", got "{last_match().group(0)}"')
    if get_pc() != pc:
        failed('the process ran after an interrupt')

# Before the first resume.
pc = get_pc()
interrupt()
cont()
expect_stop_at(pc, 'Program stopped')

# At a breakpoint.
breakpoint_at_function('main')
cont()
expect_breakpoint_stop(1)
pc = get_pc()
interrupt()
stepi()
expect_stop_at(pc, 'Program stopped')
# Reverse single steps after the first one may be done without running.
send_gdb('reverse-stepi')
send_gdb('reverse-stepi')
pc = get_pc()
interrupt()
send_gdb('reverse-stepi')
expect_stop_at(pc, 'Program stopped')

# Where the last thread is about to exit. rr reports the SIGKILL stop again
# and still reports the exit at the next continue.
send_gdb('delete 1')
send_gdb('handle SIGKILL stop')
cont()
expect_signal_stop('SIGKILL')
pc = get_pc()
interrupt()
cont()
expect_stop_at(pc, 'Program received signal SIGKILL')
interrupt()
send_gdb('reverse-stepi')
expect_stop_at(pc, 'Program received signal SIGKILL')
# When the debugger passes SIGKILL silently, rr doesn't report the SIGKILL
# stop for the interrupt, and reports the exit instead.
send_gdb('handle SIGKILL nostop noprint')
interrupt()
cont()
expect_gdb('exited normally')

ok()
