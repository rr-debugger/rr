# default rr command
rr="rr"
lib=""

function fatal { #...
    echo "$@" >&2
    exit 1
}

# check if the user supplied a custom rr command, if so use it, otherwise use default.
# $1 is number of arguments supplied to the test script
# $2 is the rr command (if exists)
function get_rr_cmd { num_args=$1; libarg=$2; rrarg=$3;
	if [ "$num_args" -gt "0" ]; then
		lib=$libarg
	fi
	if [ "$num_args" -gt "1" ]; then
		rr=$rrarg
	fi
}

# If the test takes too long to run without the syscallbuf enabled,
# use this to prevent it from running when that's the case.
function skip_if_no_syscall_buf { testname=$1
	if [[ "-n" == "$lib" || "" == "$lib" ]]; then
		echo NOTE: Skipping "'$testname'" because syscallbuf is disabled
		exit 0
	fi
}

# If the test is causing an unrealistic failure when the syscallbuf is
# enabled, skip it.  This better be a temporary situation!
function skip_if_syscall_buf { testname=$1
	if [[ "-b" == "$lib" ]]; then
		echo NOTE: Skipping "'$testname'" because syscallbuf is enabled
		exit 0
	fi
}

# compile test
# $1 is test name
# $2 are compilation flags
function compile {
	gcc -pthread -g -m32 -Wall -Werror $1.c $2 -lrt || fatal FAILED: compiling $1.c
}

# record test
function record { testname=$1; testargs=$2;
	$rr record $lib $RECORD_ARGS a.out $testargs 1> $testname.out.record
}

function delay_kill {
	sig=$1; delay_secs=$2; proc=$3

	sleep $delay_secs

	pid=""
	for i in `seq 1 5`; do
		live=`ps -C $3 -o pid=`
		num=`echo -e $live | wc -w`
		if [[ $num == 1 ]]; then
			pid=$live
			break
		fi
		sleep 0.1
	done

	if [[ $num > 1 ]]; then
		echo FAILED: more than one "'$proc'" >&2
		exit 1
	elif [[ -z "$pid" ]]; then
		echo FAILED: process "'$proc'" not located >&2
		exit 1
	fi

	kill -s $sig $pid
	if [[ $? != 0 ]]; then
		echo FAILED: signal $sig not delivered to "'$proc'" >&2
		exit 1
	fi

        echo Successfully delivered signal $sig to "'$proc'"
}

# record_async_signal <signal> <delay-secs> <test>
# record $test, delivering $signal to it after $delay-secs
function record_async_signal {
	delay_kill $1 $2 a.out &
	record $3
        wait
}

# replay test. 
# $1 is test name 
# $2 are rr flags
function replay {
	$rr replay --autopilot $2 trace_0/ 1> $1.out.replay 2> $1.err.replay
}

# debug <test-name> [rr-args]
# load the "expect" script to drive replay of the recording
function debug {
	python $1.py $rr replay --dbgport=1111 $2 trace_0/
	if [[ $? == 0 ]]; then
		echo "Test '$1' PASSED"
	else
		echo "Test '$1' FAILED"
	fi
}

# Check that (i) no error during replay; (ii) recorded and replayed
# output match; (iii) if supplied, the token was found in the output.
# Otherwise the test fails.
function check { testname=$1; token=$2;
	if [[ $(grep "Replayer successfully finished." $testname.err.replay) == "" ]]; then
		echo "Test '$testname' FAILED: error during replay:"
		echo "--------------------------------------------------"
		cat $testname.err.replay
		echo "--------------------------------------------------"
	elif [[ $(diff $testname.out.record $testname.out.replay) != "" ]]; then
		echo "Test '$testname' FAILED: output from recording different than replay"
		echo "Output from recording:"
		echo "--------------------------------------------------"
		cat $testname.out.record
		echo "--------------------------------------------------"
		echo "Output from replay:"
		echo "--------------------------------------------------"
		cat $testname.out.replay
		echo "--------------------------------------------------"
	elif [[ "$token" != "" && "$testname.out.record" != $(grep -l "$token" $testname.out.record) ]]; then
		echo "Test '$testname' FAILED: token '$token' not in output:"
		echo "--------------------------------------------------"
		cat $testname.out.record
		echo "--------------------------------------------------"
	else
		echo "Test '$testname' PASSED"
		# test passed, OK to delete temporaries
		rm -rf $testname.out.record $testname.out.replay $testname.err.replay
	fi
}

# cleanup.  we intentionally leave .record/.replay files around for
# developers to reference.
function cleanup {
	rm -rf a.out trace_0
        killall a.out rr > /dev/null 2>&1 
        # Clear $?; we don't care if, and in fact we're happy if, we
        # failed to kill malingerers.
        ls > /dev/null
}

# Compile $test.c, record it, then replay it (optionally with
# $rr_flags) and verify record/replay output match.
function compare_test { test=$1; token=$2; rr_flags=$3;
	if [[ $token == "" ]]; then
		echo "FAILED: Test $test didn't pass an exit token" >&2
		exit 1
	fi
	compile $test
	record $test
	replay $test $rr_flags
	check $test $token
	cleanup
}

# Compile $test.c, record it, then replay the recording using the
# "expect" script $test.py (optionally with $rr_flags), which is
# responsible for computing test pass/fail.
function debug_test { test=$1; rr_flags=$2;
	compile $test
	record $test
	debug $test
	cleanup
}

# Try to prevent tests that are interrupted or bail early from
# affecting this test run.
cleanup
get_rr_cmd $# $1 $2

libpath=$(realpath ../../obj/lib)
echo Using rr LD_LIBRARY_PATH "'$libpath'"
export LD_LIBRARY_PATH="$libpath:/usr/local/lib:${LD_LIBRARY_PATH}"
