#!/bin/bash

# Install the prerequisites needed to build and run tests on travis-ci.

echo Configuring travis-ci build slave ...
echo The slave is `uname -a`

packages=(rpm ccache cmake make g++-multilib pkg-config realpath zlib1g-dev)

sudo apt-get update && \
    sudo apt-get install -y "${packages[@]}" && \
    echo ... finished configuring slave
