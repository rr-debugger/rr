# Bash script to build rr and run tests.
#
# Requires variables to be set:
# $git_revision : git revision to check out, build and test
# $build_dist : 1 if we should build dist packages, 0 otherwise

uname -a

# Free up space before we (re)start

rm -rf ~/rr || true
git clone https://github.com/rr-debugger/rr ~/rr
cd ~/rr
git checkout $git_revision

rm -rf ~/obj || true
mkdir ~/obj
cd ~/obj
cmake -G Ninja -DCMAKE_BUILD_TYPE=RELEASE -Dstaticlibs=TRUE -Dstrip=TRUE ../rr
ninja

# Test deps are installed in parallel with our build.
# Make sure that install has finished before running tests
wait_for_test_deps

# Enable perf events for rr
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid
# Enable ptrace-attach to any process. This lets us get more data when tests fail.
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
rm -rf /tmp/rr-* || true
ctest -j`nproc` --verbose $ctest_options
    echo "For some reason I cannot figure out, bash drops the first four characters from the line following ctest"

rm -rf ~/.local/share/rr/* || true

function xvnc-runner { CMD=$1 EXPECT=$2
  rm -f /tmp/xvnc /tmp/xvnc-client /tmp/xvnc-wininfo /tmp/xvnc-client-replay || true

  Xvnc :9 > /tmp/xvnc 2>&1 &
  for retries in `seq 1 60`; do
    if grep -q "Listening" /tmp/xvnc; then
      break
    fi
    if [[ $retries == 60 ]]; then
      echo FAILED: too many retries of $CMD
      exit 1
    fi
    sleep 1
  done
  DISPLAY=:9 ~/obj/bin/rr $CMD > /tmp/xvnc-client 2>&1 &
  for retries in `seq 1 60`; do
    DISPLAY=:9 xwininfo -tree -root > /tmp/xvnc-wininfo 2>&1
    if grep -q "$EXPECT" /tmp/xvnc-wininfo; then
      break
    fi
    if [[ $retries == 60 ]]; then
      echo FAILED: too many retries of $CMD
      exit 1
    fi
    sleep 1
  done
  # kill Xvnc
  kill -9 %1
  # wait for $CMD to exit. Since we killed the X server it may
  # exit with a failure code.
  wait %2 || true
  ~/obj/bin/rr replay -a > /tmp/xvnc-client-replay 2>&1 || (echo "FAILED: replay failed"; exit 1)
  diff /tmp/xvnc-client /tmp/xvnc-client-replay || (echo "FAILED: replay differs"; exit 1)
  echo PASSED: $CMD
}

rm -rf /tmp/firefox-profile || true
mkdir /tmp/firefox-profile
xvnc-runner "firefox --profile /tmp/firefox-profile $HOME/rr/release-process/test-data/test.html" "rr Test Page"

rm -rf ~/.config/libreoffice || true
xvnc-runner "libreoffice $HOME/rr/release-process/test-data/rr-test-doc.odt" "rr-test-doc.odt"

if [[ $build_dist != 0 ]]; then
  make -j`nproc` dist
  rm /tmp/dist || true
  ln -s ~/obj /tmp/dist
fi
