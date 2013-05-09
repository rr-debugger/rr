#!/bin/bash

# Install the prerequisites needed to build and run tests on travis-ci.

echo Configuring travis-ci build slave ...
echo The slave is `uname -a`

sudo apt-get install libc6-dev libdisasm-dev
sudo apt-get install libc6-dev-i386

echo ... finished configuring slave
