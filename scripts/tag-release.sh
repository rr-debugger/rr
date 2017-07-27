#!/bin/bash

function fatal { why=$1;
    echo "[FATAL]" $why >&2
    exit 1
}

major=$1
minor=$2
patch=$3
ver="$major.$minor.$patch"
echo "Preparing for release '$ver' ..."
if [[ $major == "" || $minor == "" || $patch == "" ]]; then
    fatal "Usage: ./tag-release.sh MAJOR MINOR PATCH"
fi

verfile=CMakeLists.txt
echo "Patching $verfile with new version string ..."
sed -i "s/rr_VERSION_MAJOR [0-9][0-9]*/rr_VERSION_MAJOR $major/g" $verfile
sed -i "s/rr_VERSION_MINOR [0-9][0-9]*/rr_VERSION_MINOR $minor/g" $verfile
sed -i "s/rr_VERSION_PATCH [0-9][0-9]*/rr_VERSION_PATCH $patch/g" $verfile

echo "Showing diff for $verfile ..."
git diff -p -U8
echo -n "Is this what you expected to see? [Y/n] "
read ok
if [[ $ok != "Y" ]]; then
    fatal "Oops.  Aborting version update by user request."
fi

echo "Generating git commit ..."
git commit $verfile -m "Bump version to $ver."
echo "Generating git tag $ver ..."
git tag $ver

echo "Done!  Publish the new version using 'git push --all' or 'git push; git push --tags'."
