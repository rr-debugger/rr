`many-threads` creates 5000 threads and then forces 20000 ping-pongs between two of the threads. This tests performance of thread creation and context switching.

Cheat sheet:
````
cd ~/rr/obj
cmake -DCMAKE_BUILD_TYPE=RELEASE ../rr
make -j8

gcc -g -o many-threads ../rr/src/perf-test/many-threads.c
time bin/rr record ./many-threads
````
