#!/bin/bash

# Install the prerequisites needed to build and run tests on travis-ci.

echo Configuring travis-ci build slave ...
echo The slave is `uname -a`

# setup.sh will return an error code on systems that don't use yama
# ptrace hardening
sudo ./src/script/setup.sh

sudo apt-get update && \
    sudo apt-get install linux-libc-dev linux-libc-dev:i386 && \
    sudo apt-get install g++:i386 libc6-dev:i386 && \
    sudo apt-get install libdisasm-dev:i386 rpm && \
    wget http://people.mozilla.org/~gal/libpfm_4.3.0-1_amd64.deb && \
    sudo dpkg -i libpfm_4.3.0-1_amd64.deb && \
    echo ... finished configuring slave
