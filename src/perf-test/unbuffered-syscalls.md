`unbuffered-syscalls` is a simple test for the performance of handling
trivial system calls. It stresses the basic ptrace syscall-handling
machinery, and reading/writing trace events. It can also provide a basic
check of trace size. It executes 500K syscalls (i.e. 1M trace events) and
currently takes about 10 seconds to record and 8 seconds to replay on my
Skylake laptop, with an `events` file size of about 5.5 MB.

Cheat sheet:
````
cd ~/rr/obj
cmake -DCMAKE_BUILD_TYPE=RELEASE ../rr
make -j8

gcc -g -o unbuffered-syscalls ../rr/src/perf-test/unbuffered-syscalls.c
time bin/rr record ./unbuffered-syscalls
time bin/rr replay -a
ls -l ~/.local/share/rr/latest-trace/events

perf record --call-graph lbr bin/rr record ./unbuffered-syscalls
perf report
perf record --call-graph lbr bin/rr replay -a
perf report
````
