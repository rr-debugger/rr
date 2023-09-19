== counters test ==

Run with
```
g++ counters.cc -o /tmp/counters && /tmp/counters
```
This does a quick check to determine whether hardware performance counter measurement and interrupts, and the kernel/hypervisor support for them, are working as expected.

It copies some code from rr sources to make a standalone test for easy debugging and/or inclusion in CI tests for other projects. It's under the same MIT-style license as the rest of the rr code.