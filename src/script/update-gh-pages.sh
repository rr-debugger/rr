#!/bin/bash

function fatal { why=$1;
    echo "[FATAL]" $why >&2
    exit 1
}

RELDIR="releases"

major=$1
minor=$2
patch=$3
dist=$4
ver="$major.$minor.$patch"
echo "Preparing for release '$ver' ..."
if [[ $major == "" || $minor == "" || $patch == "" ]]; then
    fatal "Usage: ./update-gh-pages.sh MAJOR MINOR PATCH DIST-FILES-DIR"
fi

echo "Updating repo ..."
git fetch origin || fatal "Failed fetch from origin."
git checkout gh-pages || fatal "Failed to checkout gh-pages branch."

ARCHS="i686 x86_64"
KERNELS="Linux"
PACKS="deb rpm tar.gz"
for arch in $ARCHS; do
    for kernel in $KERNELS; do
        for pack in $PACKS; do
            package="rr-$ver-$kernel-$arch.$pack"
            if [ -f "$dist/$package" ]; then
                echo "Adding package to git ..."
                cp "$dist/$package" $RELDIR/
                git add $RELDIR/$package $RELDIR/$link
            else
                fatal "$dist/$package doesn't exist." 
            fi
        done
    done
done

verfile=index.html
echo "Patching $verfile with new version string ..."
sed -i "s/rr-[0-9]*[.][0-9]*[.][0-9]*/rr-$ver/g" $verfile

echo "Showing diff ..."
git diff -p -U8
echo "Showing status ..."
git status
echo -n "Is this what you expected to see? [Y/n] "
read ok
if [[ $ok != "Y" ]]; then
    fatal "Oops.  Aborting release by user request."
fi

git commit -a -m "Release $ver."
echo "Done!  Publish the new version using 'git push'."
