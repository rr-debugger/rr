# Building for Android

To build for Android (from the root of the rr source tree):

```
docker build .android -t rr-android
mkdir -p obj/dist
docker run -it --rm \
    -u $UID:$GID \
    -v $(pwd):/src/rr \
    -v $(pwd)/obj/dist:/dist \
    rr-android
```

`-u $UID:GID` ensures that the build runs with your current UID/GID, which is
necessary to avoid the output being only writable by root.

`-v $(pwd):/src/rr` mounts the source tree in the container so it can be built.

`-v $(pwd)/obj/dist:/dist` sets the output directory for the container to the
current directory. The last step of the build will copy the rr tarball to the
directory on the left of `:`.