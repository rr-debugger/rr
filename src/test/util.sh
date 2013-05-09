# default rr command
rr="rr"

# check if the user supplied a custom rr command, if so use it, otherwise use default.
# $1 is number of arguments supplied to the test script
# $2 is the rr command (if exists)
function get_rr_cmd {
	if [ "$1" -gt "0" ]; then
		rr=$2
	fi
}

# compile test
# $1 is test name
# $2 are compilation flags
function compile {
	gcc $1.c $2
}

# record test. 
# $1 is test name
function record {
	$rr --record a.out 1> $1.out.record
}

# replay test. 
# $1 is test name 
# $2 are rr flags
function replay {
	$rr --replay $2 trace_0/ 1> $1.out.replay 2> $1.err.replay
}

# check test success\failure.
# $1 is test name
function check {
	if [[ $(grep "Replayer successfully finished." $1.err.replay) == "" || $(diff $1.out.record $1.out.replay) != "" ]]; then
		echo "Test $1 FAILED"
	else
		echo "Test $1 PASSED"
		# test passed, OK to delete temporaries
		rm -rf $1.out.record $1.out.replay $1.err.replay
	fi
}

# cleanup.  we intentionally leave .record/.replay files around for
# developers to reference.
function cleanup {
	rm -rf a.out trace_0
}
