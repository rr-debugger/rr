# counters test

This does a quick check to determine whether hardware performance counter measurement and interrupts, and the kernel/hypervisor support for them, are working as expected. It's useful for testing PMU infrastructure without the full complexity of rr.

It copies some code from rr sources to make a standalone test for easier debugging and/or inclusion in CI tests for other projects. It's under the same MIT-style license as the rest of the rr code.

## Basic test

Run with
```
g++ counters.cc -o /tmp/counters && /tmp/counters
```

## Intensive interrupt testing

`counters` takes optional command-line parameters:
```
/tmp/counters [number of interrupts to test] [interrupt period]
```
The number of interrupts to test defaults to 1. The interrupt period defaults to 1000000.

To test interrupts thoroughly, try something like
```
for i in `seq 1 1000`; do /tmp/counters 1000 10000 > /tmp/output$i & done
```
Don't run this on your laptop! This tests 1M interrupts with the machine under load. If there are failures you will see lines like
```
[425]   Aborted                 (core dumped) ~/obj/bin/counters 1000 10000 > /tmp/output$i
```
