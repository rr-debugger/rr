FROM ubuntu:14.04
MAINTAINER Ted Mielczarek <ted@mielczarek.org>
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -qq linux-libc-dev linux-libc-dev:i386 gcc-multilib libc6-dev:i386 rpm lib32stdc++6 zlib1g:i386 zlib1g-dev:i386 python-pexpect build-essential gcc g++ gcc-4.8 g++-4.8 cmake pkg-config zlib1g-dev gdb cpp cpp-4.8
RUN ln -s /usr/lib32/libstdc++.so.6 /usr/lib32/libstdc++.so
