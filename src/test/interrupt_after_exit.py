from util import *

# Stop where the last thread is about to exit.
send_debugger('handle SIGKILL stop', 'process handle -s true SIGKILL')
cont()
expect_debugger('signal SIGKILL')

# Resume, so that rr reports the exit, and interrupt the process before the
# debugger has seen that report, as when the user interrupts just as the
# process exits. rr answers the resume with the exit report at once, so it
# gets the interrupt after the report, and must not reply to it: the report
# already answered the resume request.
if debugger_type == 'GDB':
    # gdb doesn't see the exit report while it runs a Python command, so it
    # always sends the interrupt.
    send_gdb('python gdb.execute("continue &"); gdb.execute("interrupt")')
    expect_gdb('exited normally')
    # Check that rr still answers requests, and that its replies still match
    # gdb's requests.
    send_gdb('maint packet qfThreadInfo')
    expect_gdb('received: "l"')
    restart_replay()
    expect_gdb('received signal SIGKILL')
else:
    # LLDB interrupts the process to send this packet if it still believes
    # that the process is running. It reads the exit report on another
    # thread, so it only sometimes does.
    send_lldb('script lldb.debugger.HandleCommand("process continue"); '
              'lldb.debugger.HandleCommand("process plugin packet send qC")')
    expect_debugger('exited with status = 0')

ok()
