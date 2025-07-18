#!/bin/bash

set +x # echo commands
set -e # default to exiting on error"

uname -a

EXTRA_PACKAGES=
MACHINE_TYPE=`uname -m`
if [ $MACHINE_TYPE == 'x86_64' ]; then
  EXTRA_PACKAGES=g++-multilib
fi

sudo apt-get update -y
sudo apt-get dist-upgrade -f -y
sudo apt-get install -y $EXTRA_PACKAGES cmake g++ pkg-config zlib1g-dev git python-dev-is-python3 libacl1-dev ninja-build manpages-dev capnproto libcapnp-dev gdb lldb python3-pexpect libzstd1 libzstd-dev jq

mkdir obj
cd obj
cmake -G Ninja -DCMAKE_BUILD_TYPE=DEBUG -Dstaticlibs=FALSE ..
ninja
