#!/bin/bash

# Install the prerequisites needed to build and run tests on travis-ci.

echo Configuring travis-ci build slave ...
echo The slave is `uname -a`

sudo apt-get update && \
    sudo apt-get install gcc-multilib libc6-dev:i386 libdisasm-dev:i386 && \
    echo ... finished configuring slave
