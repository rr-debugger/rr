#!/bin/bash

# Install the prerequisites needed to build and run tests on travis-ci.

echo Configuring travis-ci build slave ...
echo The slave is `uname -a`

sudo ./src/script/setup.sh && \
    apt-get update && \
    sudo apt-get install gcc-multilib libc6-dev:i386 libdisasm-dev:i386 && \
    wget https://s3-us-west-1.amazonaws.com/rr-packages/libpfm_4.3.0-1_amd64.deb && \
    sudo dpkg -i libpfm_4.3.0-1_amd64.deb && \
    ls -l /usr/local/lib/libpfm.so.4 && \
    echo ... finished configuring slave
