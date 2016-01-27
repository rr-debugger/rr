#!/bin/bash

# Install the prerequisites needed to build and run tests on travis-ci.

echo Configuring travis-ci build slave ...
echo The slave is `uname -a`

packages=(linux-libc-dev linux-libc-dev:i386
	  gcc-multilib libc6-dev:i386 rpm
	  g++ lib32stdc++6 gdb
	  zlib1g:i386 zlib1g-dev:i386
	  python-pexpect)

sudo apt-get update && \
    sudo apt-get install "${packages[@]}"
    sudo ln -s /usr/lib32/libstdc++.so.6 /usr/lib32/libstdc++.so && \
    echo ... finished configuring slave
