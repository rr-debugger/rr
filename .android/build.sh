#!/usr/bin/env bash

set +x
set +e

DEVICE_CMAKE_DEFS="-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake -DANDROID_ABI=x86_64 -DANDROID_PLATFORM=android-28"

apt-get install -y cmake g++
curl -O https://capnproto.org/capnproto-c++-0.10.2.tar.gz
tar zxf capnproto-c++-0.10.2.tar.gz
cd capnproto-c++-0.10.2
# Build capnp once for the host
./configure
make -j8
make install
cd ..
rm -rf capnproto-c++-0.10.2
tar zxf capnproto-c++-0.10.2.tar.gz
cd capnproto-c++-0.10.2
# Build capnp again for the device
cmake $DEVICE_CMAKE_DEFS -DEXTERNAL_CAPNP=True -DBUILD_SHARED_LIBS=True
make -j8
cd ..
mkdir obj
cd obj
cmake .. $DEVICE_CMAKE_DEFS \
      -Ddisable32bit=True \
      -DBUILD_TESTS=False \
      -DSKIP_PKGCONFIG=True \
      -DCAPNP_CFLAGS=-I../capnproto-c++-0.10.2/src/ \
      -DCAPNP_LDFLAGS="-L../capnproto-c++-0.10.2/src/capnp -lcapnp -L../capnproto-c++-0.10.2/src/kj -lkj" \
      -DZLIB_LDFLAGS="-lz" \
      -DEXTRA_EXTERNAL_SOLIBS="capnproto-c++-0.10.2/src/kj/libkj.so;capnproto-c++-0.10.2/src/capnp/libcapnp.so"
make -j8
cpack -G TGZ
