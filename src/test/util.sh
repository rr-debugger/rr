#
# This file is included by foo.run test-driver files.  It provides
# some helpers for common test operations.  A driver file foo.run
# will want to include this file as follows
#
#  source `dirname $0`/util.sh
#
# It is essential that util.sh inherit its $n parameters from the
# driver script's parameters.
#
# Most tests are either "compare_test"s, which check that record and
# replay successfully complete and the output is the same, or,
# "debug_test"s, which launch a debugger script.  So the remainder of
# your test runner probably looks like
#
#  compare_test  # or, |debug_test|
#
# Test runners may set the environment variable $RECORD_ARGS to pass
# arguments to rr for recording.  This is only useful for tweaking the
# scheduler, don't use it for anything else.
#

#  delay_kill <sig> <delay_secs> <proc>
#
# Deliver the signal |sig|, after waiting |delay_secs| seconds, to the
# process named |proc|.  If there's more than |proc|, the signal is
# not delivered.
function delay_kill { sig=$1; delay_secs=$2; proc=$3
    sleep $delay_secs

    pid=""
    for i in `seq 1 5`; do
        live=`ps ax -o 'pid= cmd=' | awk '{print $1 " " $2}' | grep $proc`
        num=`echo "$live" | wc -l`
        if [[ "$num" -eq 1 ]]; then
            pid=`echo "$live" | awk '{print $1}'`
            break
        fi
        sleep 0.1
    done

    if [[ "$num" -gt 1 ]]; then
        leave_data=y
        echo FAILED: "$num" of "'$proc'" >&2
        exit 1
    elif [[ -z "$pid" ]]; then
        leave_data=y
        echo FAILED: process "'$proc'" not located >&2
        exit 1
    fi

    # Wait for the test to print "ready", indicating it has completed
    # any required setup.
    until grep -q ready record.out; do
        sleep 0
    done

    kill -s $sig $pid
    if [[ $? != 0 ]]; then
        # Sometimes we fail to deliver a signal to a process because
        # it finished first (due to scheduling races). That's a benign
        # failure.
        echo signal $sig not delivered to "'$proc'", letting test succeed anyway
    else
        echo Successfully delivered signal $sig to "'$proc'"
    fi
}

function fatal { #...
    echo "$@" >&2
    exit 1
}

function onexit {
    cd
    if [[ "$leave_data" != "y" ]]; then
        rm -rf $workdir
    else
        echo Test $TESTNAME failed, leaving behind $workdir
        echo To replay the failed test, run
        echo " " _RR_TRACE_DIR="$workdir" rr replay
    fi
}

function parent_pid_of { pid=$1
    ps -p $pid -o ppid=
}

function usage {
    echo Usage: "util.sh TESTNAME [LIB_ARG] [OBJDIR]"
}

DEFAULT_FLAGS="--suppress-environment-warnings --check-cached-mmaps --fatal-errors"
# Don't bind record/replay tracees to the same logical CPU.  When we
# do that, the tests take impractically long to run.
#
# TODO: find a way to run faster with CPU binding
GLOBAL_OPTIONS="$DEFAULT_FLAGS"
# ... but tests that DO want CPU binding can override the default by
# setting
#
#   GLOBAL_OPTIONS="$GLOBAL_OPTIONS_BIND_CPU"
#
# just after sourcing this file.
GLOBAL_OPTIONS_BIND_CPU="$DEFAULT_FLAGS"

SRCDIR=`dirname $0`/../..
SRCDIR=`realpath $SRCDIR`

TESTNAME=$1
if [[ "$TESTNAME" == "" ]]; then
    [[ $0 =~ ([A-Za-z0-9_]+)\.run$ ]] || fatal "FAILED: bad test script name"
    TESTNAME=${BASH_REMATCH[1]}
fi
if [[ $TESTNAME =~ ([A-Za-z0-9_]+)_32$ ]]; then
    bitness=_32
    TESTNAME_NO_BITNESS=${BASH_REMATCH[1]}
else
    TESTNAME_NO_BITNESS=$TESTNAME
fi
LIB_ARG=$2
if [[ "$LIB_ARG" == "" ]]; then
    LIB_ARG=-b
fi
OBJDIR=$3
if [[ "$OBJDIR" == "" ]]; then
    # Default to assuming that the user's working directory is the
    # src/test/ directory within the rr clone.
    OBJDIR=`realpath $SRCDIR/../obj`
fi
if [[ ! -d "$OBJDIR" ]]; then
    fatal "FAILED: objdir missing"
fi
TIMEOUT=$4
if [[ "$TIMEOUT" == "" ]]; then
    TIMEOUT=120
fi

# The temporary directory we create for this test run.
workdir=
# Did the test pass?  If not, then we'll leave the recording and
# output around for developers to debug.
leave_data=n
# The unique ID allocated to this test directory.
nonce=

# Set up the environment and working directory.
TESTDIR="${SRCDIR}/src/test"

# Make rr treat temp files as durable. This saves copying all test
# binaries into the trace.
export RR_TRUST_TEMP_FILES=1
export PATH="${OBJDIR}/bin:${PATH}"

which rr >/dev/null 2>&1
if [[ "$?" != "0" ]]; then
    fatal FAILED: rr not found in PATH "($PATH)"
fi

if [[ ! -d $SRCDIR ]]; then
    fatal FAILED: SRCDIR "($SRCDIR)" not found. objdir and srcdir must share the same parent.
fi

if [[ ! -d $TESTDIR ]]; then
    fatal FAILED: TESTDIR "($TESTDIR)" not found.
fi

# Our test programs intentionally crash a lot. Don't generate coredumps for them.
ulimit -c 0

# NB: must set up the trap handler *before* mktemp
trap onexit EXIT
workdir=`mktemp -dt rr-test-$TESTNAME-XXXXXXXXX`
cd $workdir

# XXX technically the trailing -XXXXXXXXXX isn't unique, since there
# could be "foo-123456789" and "bar-123456789", but if that happens,
# buy me a lottery ticket.
baseworkdir=$(basename ${workdir})
nonce=${baseworkdir#rr-test-$TESTNAME-}

##--------------------------------------------------
## Now we come to the helpers available to test runners.  This is the
## testing "API".
##

function fails { why=$1;
    echo NOTE: Skipping "'$TESTNAME'" because it fails: $why
    exit 0
}

# If the test takes too long to run without the syscallbuf enabled,
# use this to prevent it from running when that's the case.
function skip_if_no_syscall_buf {
    if [[ "-n" == "$LIB_ARG" ]]; then
        echo NOTE: Skipping "'$TESTNAME'" because syscallbuf is disabled
        exit 0
    fi
}

# If the test is causing an unrealistic failure when the syscallbuf is
# enabled, skip it.  This better be a temporary situation!
function skip_if_syscall_buf {
    if [[ "-b" == "$LIB_ARG" || "" == "$LIB_ARG" ]]; then
        echo NOTE: Skipping "'$TESTNAME'" because syscallbuf is enabled
        exit 0
    fi
}

function just_record { exe="$1"; exeargs=$2;
    _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT record.err \
        rr $GLOBAL_OPTIONS record $LIB_ARG $RECORD_ARGS "$exe" $exeargs 1> record.out 2> record.err
}

function save_exe { exe=$1;
    cp "${OBJDIR}/bin/$exe" "$exe-$nonce"
}

# Record $exe with $exeargs.
function record { exe=$1;
    save_exe "$exe"
    just_record "./$exe-$nonce" "$2 $3 $4 $5"
}

#  record_async_signal <signal> <delay-secs> <test>
#
# Record $test, delivering $signal to it after $delay-secs.
# If for some reason delay_kill doesn't run in time, the signal
# will not be delivered but the test will not be aborted.
function record_async_signal { sig=$1; delay_secs=$2; exe=$3; exeargs=$4;
    delay_kill $sig $delay_secs $exe-$nonce &
    record $exe $exeargs
    wait
}

function replay { replayflags=$1
    _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT replay.err \
        rr $GLOBAL_OPTIONS replay -a $replayflags 1> replay.out 2> replay.err
}

function do_ps { psflags=$1
    _RR_TRACE_DIR="$workdir" \
        rr $GLOBAL_OPTIONS ps $psflags
}

#  debug <expect-script-name> [replay-args]
#
# Load the "expect" script to drive replay of the recording of |exe|.
function debug { expectscript=$1; replayargs=$2
    _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT debug.err \
        python2 $TESTDIR/$expectscript.py \
        rr $GLOBAL_OPTIONS replay -o-n -x $TESTDIR/test_setup.gdb $replayargs
    if [[ $? == 0 ]]; then
        passed
    else
        failed "debug script failed"
        echo "--------------------------------------------------"
        echo "gdb_rr.log:"
        cat gdb_rr.log
        echo "--------------------------------------------------"
        echo "debug.err:"
        cat debug.err
        echo "--------------------------------------------------"
    fi
}

function failed { msg=$1;
    leave_data=y
    echo "Test '$TESTNAME' FAILED: $msg"
}

function passed {
    echo "Test '$TESTNAME' PASSED"
}

# Check that (i) no error during replay; (ii) recorded and replayed
# output match; (iii) the supplied token was found in the output.
# Otherwise the test fails.
function check { token=$1;
    if [ ! -f record.out -o ! -f replay.err -o ! -f replay.out -o ! -f record.err ]; then
        failed "output files not found."
    elif [[ $(cat record.err) != "" ]]; then
        failed ": error during recording:"
        echo "--------------------------------------------------"
        cat record.err
        echo "--------------------------------------------------"
        echo "record.out:"
        echo "--------------------------------------------------"
        cat record.out
        echo "--------------------------------------------------"
    elif [[ "$token" != "" && "record.out" != $(grep -l "$token" record.out) ]]; then
        failed ": token '$token' not in record.out:"
        echo "--------------------------------------------------"
        cat record.out
        echo "--------------------------------------------------"
    elif [[ $(cat replay.err) != "" ]]; then
        failed ": error during replay:"
        echo "--------------------------------------------------"
        cat replay.err
        echo "--------------------------------------------------"
        echo "replay.out:"
        echo "--------------------------------------------------"
        cat replay.out
        echo "--------------------------------------------------"
    elif [[ $(diff record.out replay.out) != "" ]]; then
        failed ": output from recording different than replay"
        echo "diff -U8 $workdir/record.out $workdir/replay.out"
        diff -U8 record.out replay.out
    else
        passed
    fi
}

#  compare_test <token> [<replay-flags>] [executable]
#
# Record the test name passed to |util.sh|, then replay it (optionally
# with $replayflags) and verify record/replay output match and $token
# appears in the output. Uses $executable instead of the passed-in testname
# if present.
function compare_test { token=$1; replayflags=$2;
    test=$TESTNAME
    if (( $# >= 3 )); then
        test=$3
    fi
    if [[ $token == "" ]]; then
        failed ": didn't pass an exit token"
    fi
    record $test
    replay $replayflags
    check $token
}

#  debug_test
#
# Record the test name passed to |util.sh|, then replay the recording
# using the "expect" script $test-name.py, which is responsible for
# computing test pass/fail.
function debug_test {
    record $TESTNAME
    debug $TESTNAME_NO_BITNESS
}

# Return the number of events in the most recent local recording.
function count_events {
    local events=$(rr $GLOBAL_OPTIONS dump -r latest-trace | wc -l)
    # The |simple| test is just about the simplest possible C program,
    # and has around 180 events (when recorded on a particular
    # developer's machine).  If we count a number of events
    # significalty less than that, almost certainly something has gone
    # wrong.
    if [ "$events" -le 150 ]; then
        failed ": Recording had too few events.  Is |rr dump -r| broken?"
    fi
    # This event count is used to loop over attaching the debugger.
    # The tests assume that the debugger can be attached at all
    # events, but at the very last events, EXIT and so forth, rr can't
    # attach the debugger.  So we fudge the event count down to avoid
    # that edge case.
    let "events -= 10"
    echo $events
}

# Return a random number from the range [min, max], inclusive.
function rand_range { min=$1; max=$2
    local num=$RANDOM
    local range=""
    let "range = 1 + $max - $min"
    let "num %= $range"
    let "num += $min"
    echo $num
}

# Record |exe|, then replay it using the |restart_finish| debugger
# script attaching at every recorded event.  To make the
# debugger-replays more practical, the events are strided between at a
# random interval between [min, max], inclusive.
#
# So for example, |checkpoint_test simple 3 5| means to record the
# "simple" test, and attach the debugger at every X'th event, where X
# is a random number in [3, 5].
function checkpoint_test { exe=$1; min=$2; max=$3;
    record $exe
    num_events=$(count_events)
    stride=$(rand_range $min $max)
    for i in $(seq 1 $stride $num_events); do
        echo Checkpointing at event $i ...
        debug restart_finish "-g $i"
        if [[ "$leave_data" == "y" ]]; then
            break
        fi
    done
}
