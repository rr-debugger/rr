# Bash script to build rr and run tests.
#
# Requires variables and functions to be set. See test-system.py.
# $git_revision : git revision to check out, build and test
# $staticlibs : TRUE or FALSE to build with static libs
# $build_dist : 1 if we should build dist packages, 0 otherwise
# $test_firefox : 1 to run firefox tests, 0 to skip
# $ctest_options : options to pass to ctest, e.g to exclude certain tests
# $cpack_generators : CPack generators to build dist
# setup_commands : function to setup environment, e.g. 'apt update'
# install_build_deps : function to install dependencies required to build rr
# install_app_test_deps : function to install dependencies required by tests

set -x # echo commands
set -e # default to exiting on error"

uname -a

setup_commands
install_build_deps

install_app_test_deps & # job %1

# Free up space before we (re)start

rm -rf ~/rr || true
git clone https://github.com/rr-debugger/rr ~/rr
cd ~/rr
git checkout $git_revision

rm -rf ~/obj || true
mkdir ~/obj
cd ~/obj
cmake -G Ninja -DCMAKE_BUILD_TYPE=RELEASE -Dstaticlibs=$staticlibs -Dstrip=TRUE -DCPACK_GENERATOR=$cpack_generators ../rr
ninja

# Enable perf events for rr
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid
# Enable ptrace-attach to any process. This lets us get more data when tests fail.
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
rm -rf /tmp/rr-* || true
ctest -j`nproc` --verbose $ctest_options
    echo "For some reason I cannot figure out, bash drops the first four characters from the line following ctest"

# Integration test deps are installed in parallel with our build.
# Make sure that install has finished before running tests
wait %1

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

if [[ $test_firefox == 1 ]]; then
  rm -rf /tmp/firefox /tmp/firefox-profile || true
  mkdir /tmp/firefox-profile
  ( cd /tmp; curl -L 'https://download.mozilla.org/?product=firefox-latest&os=linux64&lang=en-US' | tar -jxf - )
  xvnc-runner "/tmp/firefox/firefox --profile /tmp/firefox-profile $HOME/rr/release-process/test-data/test.html" "rr Test Page"
fi

if [[ $test_libreoffice == 1 ]]; then
  rm -rf ~/.config/libreoffice || true
  xvnc-runner "libreoffice $HOME/rr/release-process/test-data/rr-test-doc.odt" "rr-test-doc.odt"
fi

if [[ $build_dist != 0 ]]; then
  ninja package
  rm /tmp/dist || true
  ln -s ~/obj/dist /tmp/dist
fi
