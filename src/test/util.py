import pexpect, re, signal, sys, time

__all__ = [ 'expect_rr', 'expect_list', 'expect_debugger',
            'restart_replay', 'interrupt_gdb', 'expect_gdb', 'send_gdb',
            'ok', 'failed', 'iterlines_both', 'last_match', 'get_exe_arch',
            'get_gdb_version', 'breakpoint_at_function',
            'watchpoint_at_address', 'cont', 'backtrace', 'up',
            'expect_breakpoint_stop', 'expect_watchpoint_stop',
            'delete_watchpoint', 'set_breakpoint_commands',
            'expect_expression' ]

# Don't use python timeout. Use test-monitor timeout instead.
TIMEOUT_SEC = 10000
# The debugger and rr are part of the same process tree, so they share
# stdin/stdout.
child = None
debugger_type = 'GDB'

# Public API
def expect_debugger(what):
    expect(child, what)

def expect_list(pats):
    return child.expect_list(pats)

def expect_rr(what):
    expect(child, what)

def failed(why, e=None):
    print('FAILED:', why)
    if e:
        print('exception:', e)
    clean_up()
    sys.exit(1)

def interrupt_debugger():
    try:
        child.kill(signal.SIGINT)
    except Exception as e:
        failed('interrupting debugger', e)
    expect_gdb('stopped.')

def iterlines_both():
    return child

def last_match():
    return child.match

def expect_gdb(what):
    assert debugger_type == 'GDB'
    expect_debugger(what)

def interrupt_gdb():
    assert debugger_type == 'GDB'
    interrupt_debugger()

def send_gdb(what):
    assert debugger_type == 'GDB'
    send(child, "%s\n"%what)

def send_lldb(what):
    assert debugger_type == 'LLDB'
    send(child, "%s\n"%what)

# Restarts and continues execution
def restart_replay(event=0):
    if event:
        send_gdb('r %d'%(event))
    else:
        send_gdb('r')
    # gdb may not prompt here. It's ok to send an unnecessary 'y'
    # since there is no such command.
    send_gdb('y')
    # Wait to see 'stopped'. We don't want this to get buffered up
    # so callers expecting a 'stopped' *after* replay has resumed
    # get confused.
    expect_rr('stopped')
    send_gdb('c')

def breakpoint_at_function(function):
    send_debugger(f'break {function}', f'breakpoint set --name {function}')
    expect_debugger(r'Breakpoint (\d+)')
    return int(last_match().group(1))

size_to_type = {1: 'char', 2:'short', 4:'int', 8:'long long'}

def watchpoint_at_address(address, size):
    send_debugger(f'watch -l *({size_to_type[size]}*){address}',
                  f'watchpoint set expression -s {size} -- {address}')
    expect_debugger(r'atchpoint (\d+)')
    return int(last_match().group(1))

def delete_watchpoint(watchpoint):
    send_debugger(f'delete {watchpoint}', f'watchpoint delete {watchpoint}')

def cont():
    send_debugger('continue', 'continue')

def up():
    send_debugger('up', 'up')

def backtrace():
    send_debugger('bt', 'thread backtrace')

def expect_breakpoint_stop(number):
    if debugger_type == 'GDB':
        expect_debugger("Breakpoint %d"%number)
    else:
        expect_debugger("stop reason = breakpoint %d"%number)

def expect_watchpoint_stop(number):
    if debugger_type == 'GDB':
        expect_debugger("atchpoint %d"%number)
    else:
        expect_debugger("stop reason = watchpoint %d"%number)

def set_breakpoint_commands(number, commands):
    if debugger_type == 'GDB':
        send_gdb(f'commands {number}')
        for command in commands:
            send_gdb(command)
        send_gdb('end')
    else:
        send_lldb(f'breakpoint command add {number}')
        expect_debugger('Enter your debugger command')
        for command in commands:
            send_lldb(command)
        send_lldb('DONE')
        expect_debugger('(rr)')

def send_debugger(gdb_cmd, lldb_cmd):
    if debugger_type == 'GDB':
        send_gdb(gdb_cmd)
    else:
        send_lldb(lldb_cmd)

def ok():
    send_debugger('quit', 'quit')
    send_debugger('y', 'y')
    clean_up()

def get_exe_arch():
    send_gdb('show architecture')
    expect_gdb(r'The target architecture is set (automatically|to "auto") \(currently "?([0-9a-z:-]+)"?\)\.?')
    global child
    return child.match.group(2)

def get_gdb_version():
    '''Return the gdb version'''
    send_gdb('python print(gdb.VERSION)')
    expect_gdb(r'(\d+.\d+)')
    global child
    return float(child.match.group(1))

# Internal helpers
def clean_up():
    global child
    iterations = 0
    while child:
        try:
            # FIXME: without this sleep python freezes instead of exiting.
            # The sleep has to be before BufferedRWPair.close()
            time.sleep(0.1)
            child.close(force=1)
            child = None
        except Exception as e:
            if iterations < 5:
                print("close() failed with '%s', retrying..."%e)
                iterations = iterations + 1
            else:
                child = None

def expect(prog, what):
    try:
        prog.expect(what)
    except Exception as e:
        failed('expecting "%s"'% (what), e)

def send(prog, what):
    try:
        prog.send(what)
    except Exception as e:
        failed('sending "%s"'% (what), e)

def set_up():
    global child
    global debugger_type
    args = sys.argv[1:]
    log_file = 'gdb_rr.log'
    if args[0] == '--lldb':
        debugger_type = 'LLDB'
        args = args[1:] + ['-d', 'lldb', '-o', '--no-use-colors']
        log_file = 'lldb_rr.log'
    try:
        child = pexpect.spawn(args[0], args[1:], codec_errors='ignore',
            timeout=TIMEOUT_SEC, encoding='utf-8', logfile=open(log_file, 'w'))
        child.delaybeforesend = 0
        expect_debugger(r'\(rr\)')
    except Exception as e:
        failed('initializing rr and debugger', e)

set_up()
