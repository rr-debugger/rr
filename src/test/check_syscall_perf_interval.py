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
syscall_re = re.compile("`SYSCALL: " + syscall + "' \\(state:0\\)")
perfctr_re = re.compile(counter + ":(\\d+)")

while True:
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    if syscall_re.search(line):
        line = sys.stdin.readline()
        m = perfctr_re.search(line)
        if m:
            v = int(m.group(1))
            if last_perfctr_value >= 0 and v - last_perfctr_value != expected_count:
                print "Mismatch: %d - %d is not %d" % (v, last_perfctr_value, expected_count)
                sys.exit(1)
            last_perfctr_value = v
