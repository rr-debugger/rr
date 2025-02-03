FROM ubuntu:latest

ARG ndk_version=r27c

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    cmake \
    ninja-build \
    python3 \
    unzip

RUN curl -o ndk.zip https://dl.google.com/android/repository/android-ndk-${ndk_version}-linux.zip
RUN unzip ndk.zip && mv android-ndk-${ndk_version} /ndk

RUN curl -o capnproto.tar.gz https://capnproto.org/capnproto-c++-0.10.2.tar.gz
RUN mkdir -p /src/capnproto
RUN tar zxf capnproto.tar.gz -C /src/capnproto --strip-components=1
RUN mkdir -p /build/capnproto
RUN cd /build/capnproto
RUN /src/capnproto/configure
RUN make -j$(nproc) install
RUN cd -

RUN mkdir -p /build/rr
RUN chmod 777 /build/rr

WORKDIR /build/rr
CMD ["/bin/bash", "/src/rr/.android/build.sh"]
