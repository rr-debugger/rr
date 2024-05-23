#!/bin/bash

set +x # echo commands
set -e # default to exiting on error"

# Enable perf events for rr
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid > /dev/null
# Enable ptrace-attach to any process. This lets us get more data when tests fail.
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope > /dev/null
# Disable AppArmor restrictions on user namespaces, which our tests need to use
(echo 0 | sudo tee /proc/sys/kernel/apparmor_restrict_unprivileged_userns) > /dev/null || true
let halfproc=`nproc`/2
cd obj
ctest -j$halfproc --verbose
