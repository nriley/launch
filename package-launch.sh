#!/bin/zsh -e

set -x -v

find . -name \*~ -exec rm '{}' \;
xcodebuild -configuration Deployment clean
xcodebuild -configuration Deployment DSTROOT=/ "INSTALL_PATH=$PWD" install
SetFile -c 'ttxt' -t 'TEXT' README VERSION launch.1
sudo /usr/bin/install -d /usr/local/bin /usr/local/man/man1
sudo /usr/bin/install launch /usr/local/bin
sudo /usr/bin/install -m 644 launch.1 /usr/local/man/man1
chmod 755 launch
chmod 644 launch.1
VERSION=`cat VERSION` TARBALL="$PWD/launch-$VERSION.tar.gz"
rm -f ../launch-$VERSION $TARBALL
ln -s $PWD ../launch-$VERSION
cd ..
/usr/bin/tar \
    --exclude=.DS_Store --exclude=.git\* --exclude=.gdb_history \
    --exclude=build --exclude=\*.xcworkspace --exclude=xcuserdata \
    --exclude=launch-\*.tar.gz \
    -zcLf $TARBALL launch-$VERSION
rm -f launch-$VERSION
scp $TARBALL osric:web/nriley/software/
