#!/usr/bin/env python2

import sys
import multiprocessing
import tempfile
import subprocess
import copy
import shutil
import os
import itertools

objdir = sys.argv[1]
sanity_runs = eval(sys.argv[2])
runs = eval(sys.argv[3])
name = sys.argv[4]
params = sys.argv[5:]

GOOD_FAIL = 77

# Runs test, returns True if the test passed, False if it
# expectedly fails. Exits with code 1 if test unexpectedly failed.
def run(rr_params):
    d = tempfile.mkdtemp(prefix='rr-chaos-')
    try:
        env = copy.copy(os.environ)
        env['_RR_TRACE_DIR'] = d
        with open(d + "/out", 'w') as out:
            p = subprocess.Popen(["%s/bin/rr"%objdir, "record"] + rr_params + ["%s/bin/%s"%(objdir, name)] + params, env=env,
                stdout=out, stderr=out)
            ret = p.wait()
        if ret != 0 and ret != GOOD_FAIL:
            print "Test %s failed unexpectedly; leaving behind trace in %s"%(name, d)
        out_array = []
        with open(d + "/out", 'r') as out:
            for line in out:
                out_array.append(line)
        return [ret, out_array]
    finally:
        shutil.rmtree(d)

# Use only half the cores. Otherwise tests will induce starvation
# themselves; we want to measure starvation induced by rr.
pool = multiprocessing.Pool(max(1, multiprocessing.cpu_count()/2))

def safe_exit(code):
    pool.terminate()
    pool.join()
    sys.exit(code)

print "Running %d iterations of %s/bin/%s %s without chaos mode"%(sanity_runs, objdir, name, ' '.join(params))
sanity_failed = 0
for r in pool.imap_unordered(run, itertools.repeat([], sanity_runs)):
    if r[0] == 0:
        continue
    if r[0] != GOOD_FAIL:
        safe_exit(r[0])
        break
    sanity_failed = sanity_failed + 1
if sanity_failed == sanity_runs:
    print "PROBLEM: %d runs of %s all failed; not a good chaos mode test"%(sanity_failed, name)
    safe_exit(2)
print "Without chaos mode, %d runs of %s failed out of %d"%(sanity_failed, name, sanity_runs)

print "Running %d iterations of %s/bin/%s %s in chaos mode"%(runs, objdir, name, ' '.join(params))
failed = 0
for r in pool.imap_unordered(run, itertools.repeat(["--chaos"], runs)):
    if r[0] == 0:
        continue
    if r[0] != GOOD_FAIL:
        safe_exit(r[0])
        break
    if failed == 0:
        print "First test failure detected, output:"
        for line in r[1]:
            print line,
    failed = failed + 1
if failed == 0:
    print "PROBLEM: With chaos mode, test %s did not fail in %d runs"%(name, runs)
    safe_exit(1)

print "With chaos mode, %d runs of %s failed out of %d"%(failed, name, runs)
if float(failed)/runs < 3*float(sanity_failed)/sanity_runs:
    print "PROBLEM: Chaos mode didn't really help!"
    safe_exit(3)

safe_exit(0)
print
