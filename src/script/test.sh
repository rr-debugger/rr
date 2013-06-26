#!/bin/bash

while [[ $# > 0 ]] ; do
	case $1 in
		-dir=*)     dir=${1#-dir=} ;    shift 1 ;;
		-h)         usage=1 ;            shift 1 ;;
		-lib=*)     lib=${1#-lib=} ;    shift 1 ;;
		-rr=*)      rr=${1#-rr=} ;      shift 1 ;;
		*)                              shift 1 ;;
	esac
done

if [ -n "$usage" ]; then
	echo "Usage: test.sh [-dir=test_directory] [-rr=rr_command] [-lib=filter_lib]"
	echo "Runs rr standard tests."
	echo "Default rr command is 'rr'"
	echo "Default test directory is '../test/'"
	exit 0
fi

# find the rr command, if not given
if [ -z $rr ]; then
	rr=rr
fi

# find the tests dir, if not given
if [ -z $dir ]; then
	dir=../test/
fi

if [[ "$lib" == "y" ]]; then
	lib="-b"                # force-enable
elif [[ "$lib" == "n" ]]; then
	lib="-n"                # force-disable
# else, rr default
fi

#move to test directory
cd $dir

# record and replay all tests
for test in *.run; do
	bash $test "$lib" $rr
done
