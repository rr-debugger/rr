#!/bin/bash

function fatal { why=$1;
    echo "[FATAL]" $why >&2
    exit 1
}

rev=HEAD
if [[ $1 != "" ]]; then
  rev=$1
fi
ver=`git name-rev --name-only --tags $rev`
if [[ $ver == undefined ]]; then
  fatal "No tag found"
fi

echo "Updating repo ..."
git checkout gh-pages || fatal "Failed to checkout gh-pages branch."

verfile=index.html
echo "Patching $verfile with new version $ver ..."
sed -i "s/<span class=ver>[^<]*</<span class=ver>$ver</g" index.html

echo "Showing diff ..."
git diff -p -U8
echo -n "Is this what you expected to see? [Y/n] "
read ok
if [[ $ok != "Y" ]]; then
    fatal "Oops.  Aborting release by user request."
fi

git commit -a -m "Release $ver."
echo "Done!  Publish the new version using 'git push'."
