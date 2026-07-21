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
  cd /tmp
  rm rr-test-cpu-lock || true
  for dir in rr-test-*; do
    echo "Packing test /tmp/$dir"
    $GITHUB_WORKSPACE/obj/bin/rr pack $dir/latest-trace
    tar zcf $GITHUB_WORKSPACE/failed-tests/$dir.tar.gz $dir
    rm -rf $dir
  done
fi

# Uncomment to retrieve CTestCostData for git inclusion, filters out all times less than 10 seconds.
#mkdir -p $GITHUB_WORKSPACE/failed-tests
#cat Testing/Temporary/CTestCostData.txt | grep -v -E ".* [0-9]\.[0-9]*|---" \
#  | awk '{print $1 " " 1 " " gensub(/(.*)\.(.).*/, "\\1.0", "g", $3) }' \
#  | sort > $GITHUB_WORKSPACE/failed-tests/rr-test-ctestcostdata.txt
#STATUS=1  # to trigger artifacts creation, if all tests succeeded

exit $STATUS
