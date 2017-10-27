import pexpect, re, signal, sys, time

__all__ = [ 'expect_gdb', 'send_gdb','expect_rr', 'expect_list',
            'restart_replay', 'interrupt_gdb', 'ok',
            'failed', 'iterlines_both', 'last_match', 'get_exe_arch' ]

# Public API
def expect_gdb(what):
    expect(gdb_rr, what)

def expect_list(pats):
    return gdb_rr.expect_list(pats)

def expect_rr(what):
    expect(gdb_rr, what)

def failed(why, e=None):
    print 'FAILED:', why
    if e:
        print 'exception:', e
    clean_up()
    sys.exit(1)

def interrupt_gdb():
    try:
        gdb_rr.kill(signal.SIGINT)
    except Exception, e:
        failed('interrupting gdb', e)
    expect_gdb('stopped.')

def iterlines_both():
    return gdb_rr

def last_match():
    return gdb_rr.match

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

def send_gdb(what):
    send(gdb_rr, "%s\n"%what)

def ok():
    send_gdb('q')
    send_gdb('y')
    clean_up()

# Internal helpers
# Don't use python timeout. Use test-monitor timeout instead.
TIMEOUT_SEC = 10000
# gdb and rr are part of the same process tree, so they share
# stdin/stdout.
gdb_rr = None

def clean_up():
    global gdb_rr
    iterations = 0
    while gdb_rr:
        try:
            # FIXME: without this sleep python freezes instead of exiting.
            # The sleep has to be before BufferedRWPair.close()
            time.sleep(0.1)
            gdb_rr.close(force=1)
            gdb_rr = None
        except Exception, e:
            if iterations < 5:
                print "close() failed with '%s', retrying..."%e
                iterations = iterations + 1
            else:
                gdb_rr = None

def expect(prog, what):
    try:
        prog.expect(what)
    except Exception, e:
        failed('expecting "%s"'% (what), e)

def get_exe_arch():
    send_gdb('show architecture')
    expect_gdb('The target architecture is set automatically \\(currently ([0-9a-z:-]+)\\)')
    global gdb_rr
    return gdb_rr.match.group(1)

def get_rr_cmd():
    '''Return the command that should be used to invoke rr, as the tuple
  (executable, array-of-args)'''
    rrargs = sys.argv[1:]
    return (rrargs[0], rrargs[1:])

def send(prog, what):
    try:
        prog.send(what)
    except Exception, e:
        failed('sending "%s"'% (what), e)

def set_up():
    global gdb_rr
    try:
        gdb_rr = pexpect.spawn(*get_rr_cmd(), timeout=TIMEOUT_SEC, logfile=open('gdb_rr.log', 'w'))
        gdb_rr.delaybeforesend = 0
        expect_gdb(r'\(rr\)')
    except Exception, e:
        failed('initializing rr and gdb', e)

set_up()
