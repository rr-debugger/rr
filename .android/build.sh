#!/usr/bin/env bash
set -e
set -x

DEVICE_CMAKE_DEFS="-DCMAKE_TOOLCHAIN_FILE=/ndk/build/cmake/android.toolchain.cmake -DANDROID_ABI=x86_64 -DANDROID_PLATFORM=android-28"

# Build capnp again for the device
INSTALL_PREFIX=$(pwd)/install
mkdir -p $INSTALL_PREFIX
mkdir capnproto-android
cd capnproto-android
cmake -G Ninja \
  $DEVICE_CMAKE_DEFS \
  -DEXTERNAL_CAPNP=True \
  -DBUILD_SHARED_LIBS=True \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
  /src/capnproto
cmake --build .
cmake --install .
cd -

mkdir obj
cd obj
cmake -G Ninja \
  $DEVICE_CMAKE_DEFS \
  -Ddisable32bit=True \
  -DBUILD_TESTS=False \
  -DCMAKE_FIND_ROOT_PATH=$INSTALL_PREFIX \
  -DSKIP_PKGCONFIG=True \
  -DEXTRA_VERSION_STRING="$BUILD_ID" \
  -DZLIB_LDFLAGS=-lz \
  /src/rr
cmake --build .
cpack -G TGZ

cp dist/* /dist/