import sys
import re

if len(sys.argv) < 4:
    print '''Usage: %s <syscall-name> <perf-counter-name> <expected-perf-events-between-syscalls>
Exits with status 0 if exactly the expected number of perf events occur between
every pair of consecutive system calls of the given type.''' % sys.argv[0]
    sys.exit(2)

syscall = sys.argv[1]
counter = sys.argv[2]
expected_count = int(sys.argv[3])

last_perfctr_value = -1
syscall_re = re.compile("`SYSCALL: (\\w+)' \\(state:0\\)")
perfctr_re = re.compile(counter + ":(\\d+)")

while True:
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    m = syscall_re.search(line)
    if m:
        if m.group(1) == syscall:
            line = sys.stdin.readline()
            m = perfctr_re.search(line)
            if m:
                v = int(m.group(1))
                if last_perfctr_value >= 0 and v - last_perfctr_value != expected_count:
                    print "Mismatch: saw %d %ss between %ss (from %d to %d), expected %d" % \
                      (v - last_perfctr_value, counter, syscall, last_perfctr_value, v, expected_count)
                    sys.exit(1)
                last_perfctr_value = v
        else:
            # Ignore nonconsecutive syscalls. In the cpuid test, we have
            # two batches of geteuid32s; one injected by rr itself to detect
            # a buggy system, and a separate one for the test. We need to
            # ignore the geteuid32 pair that spans the gap between the batches.
            last_perfctr_value = -1
