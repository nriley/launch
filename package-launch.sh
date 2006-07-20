#!/bin/zsh

set -x -v

cd launch && \
find . -name \*~ -exec rm '{}' \; && \
xcodebuild -configuration Deployment clean && \
xcodebuild -configuration Deployment DSTROOT=/ "INSTALL_PATH=$PWD" install && \
SetFile -c 'R*ch' -t 'TEXT' README VERSION launch.1 && \
sudo /usr/bin/install -c launch /usr/local/bin && \
sudo /usr/bin/install -c launch.1 /usr/local/man/man1 && \
chmod 755 launch && \
chmod 644 launch.1 && \
rm -rf build/launch.build build/intermediates build/.gdb_history && \
VERSION=`cat VERSION` TARBALL="launch-$VERSION.tar.gz" && \
cd .. && \
rm -f launch-$VERSION $TARBALL $DMG && \
ln -s launch launch-$VERSION && \
tar --owner=root --group=wheel --exclude=.DS_Store --exclude=.svn --exclude=.gdb_history -zchf launch-$VERSION.tar.gz launch-$VERSION && \
scp $TARBALL ainaz:web/nriley/software/ #$DMG 
: