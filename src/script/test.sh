#!/bin/bash
echo "Usage: test.sh [-dir=test_directory] [-rr=rr_command]"
echo "Runs rr standard tests."
echo "Default rr command is 'rr'"
echo "Default test directory is '../test/'"
echo "-----------------------------------------------------"

while [[ $# > 0 ]] ; do
	case $1 in
		-dir=*)     dir=${1#-dir=} ;    shift 1 ;;
		-rr=*)      rr=${1#-rr=} ;      shift 1 ;;
		*)                              shift 1 ;;
	esac
done

# find the rr command, if not given
if [ -z $rr ]; then
	rr=rr
fi

# find the tests dir, if not given
if [ -z $dir ]; then
	dir=../test/
fi

#move to test directory
cd $dir

# record and replay all tests
for test in *.run; do
	source $test $rr
done
