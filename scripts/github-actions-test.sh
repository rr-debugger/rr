#!/bin/bash

set +x # echo commands

# Enable perf events for rr
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid > /dev/null
# Enable ptrace-attach to any process. This lets us get more data when tests fail.
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope > /dev/null
# Disable AppArmor restrictions on user namespaces, which our tests need to use
(echo 0 | sudo tee /proc/sys/kernel/apparmor_restrict_unprivileged_userns) > /dev/null || true
let halfproc=`nproc`/2
cd obj
mkdir -p Testing/Temporary
mv ../scripts/github-actions-CTestCostData.txt Testing/Temporary/CTestCostData.txt
ctest -j$halfproc --verbose

STATUS=$?
if [[ $STATUS != 0 ]]; then
  mkdir $GITHUB_WORKSPACE/failed-tests
  #cp -a Testing/Temporary/CTestCostData.txt $GITHUB_WORKSPACE/failed-tests/rr-test-ctestcostdata.txt
  cd /tmp
  rm rr-test-cpu-lock || true
  for dir in rr-test-*; do
    echo "Packing test /tmp/$dir"
    $GITHUB_WORKSPACE/obj/bin/rr pack $dir/latest-trace
    tar zcf $GITHUB_WORKSPACE/failed-tests/$dir.tar.gz $dir
    rm -rf $dir
  done
fi

exit $STATUS
