`many-threads-wake` creates 5000 threads. Each new thread has to wait for the creator thread to exit a critical section before proceeding.

Cheat sheet:
````
cd ~/rr/obj
cmake -DCMAKE_BUILD_TYPE=RELEASE ../rr
make -j8

gcc -g -o many-threads-wake ../rr/src/perf-test/many-threads-wake.c
time bin/rr record ./many-threads-wake
````
