import pexpect, re, signal, sys, time

__all__ = [ 'expect_gdb', 'send_gdb','expect_rr', 'send_rr', 'expect_list',
            'restart_replay', 'restart_replay_at_end', 'interrupt_gdb', 'ok',
            'failed', 'iterlines_both', 'last_match' ]

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

def restart_replay(event=0):
    if event:
        send_gdb('r %d\n'%(event))
    else:
        send_gdb('r\n')
    expect_gdb('Start it from the beginning')
    send_gdb('y\n')

def restart_replay_at_end():
    # gdb doesn't prompt if it thinks the inferior has exited.
    send_gdb('r\n')

def send_gdb(what):
    send(gdb_rr, what)

def send_rr(what):
    send(gdb_rr, what)

def ok():
    send_gdb('q\n')
    send_gdb('y\n')
    clean_up()

# Internal helpers
TIMEOUT_SEC = 20
# gdb and rr are part of the same process tree, so they share
# stdin/stdout.
gdb_rr = None

def clean_up():
    global gdb_rr
    iterations = 0
    while gdb_rr:
        try:
            gdb_rr.close(force=1)
            gdb_rr = None
        except ExceptionPexpect, e:
            if iterations < 5:
                print "close() failed with '%s', retrying..."%e
                ++iterations
            else:
                raise e

def expect(prog, what):
    try:
        prog.expect(what)
    except Exception, e:
        failed('expecting "%s"'% (what), e)

def get_exe():
    '''Return the image to be debugged'''
    return sys.argv[1]

def get_rr_cmd():
    '''Return the command that should be used to invoke rr, as the tuple
  (executable, array-of-args)'''
    rrargs = sys.argv[2:]
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
        expect_gdb(r'\(gdb\)')
    except Exception, e:
        failed('initializing rr and gdb', e)

set_up()
