#!/bin/sh

# Chaos tests take a long time to run, and by their very nature they're
# nondeterministic and may fail intermittently, so they aren't part of 'make
# check'. For realistic results, run the tests on a machine that's otherwise
# idle.
#
# Usage: chaos-test.sh <path-to-rr-objdir>

cd `dirname $0`

python harness.py $1 40 40 core_count 3
echo
python harness.py $1 500 500 mmap_bits 7
echo
python harness.py $1 500 500 mmap_adjacent 10
echo
python harness.py $1 100 200 starvation_singlethreaded 200000 202000 2000 1000000
echo
python harness.py $1 100 200 starvation_singlethreaded 2000000 2400000 500000 5000000
echo
python harness.py $1 400 800 starvation_multithreaded 200000 202000 2000 1000000
echo
python harness.py $1 400 1600 starvation_multithreaded 2000000 2400000 500000 5000000
