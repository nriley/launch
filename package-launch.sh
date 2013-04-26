#!/bin/zsh

set -x -v

cd launch && \
find . -name \*~ -exec rm '{}' \; && \
xcodebuild -configuration Deployment clean && \
xcodebuild -configuration Deployment DSTROOT=/ "INSTALL_PATH=$PWD" install && \
SetFile -c 'ttxt' -t 'TEXT' README VERSION launch.1 && \
sudo /usr/bin/install -d /usr/local/bin /usr/local/man/man1 && \
sudo /usr/bin/install launch /usr/local/bin && \
sudo /usr/bin/install -m 644 launch.1 /usr/local/man/man1 && \
chmod 755 launch && \
chmod 644 launch.1 && \
VERSION=`cat VERSION` TARBALL="launch-$VERSION.tar.gz" && \
cd .. && \
rm -f launch-$VERSION $TARBALL && \
ln -s launch launch-$VERSION && \
tar --owner=root --group=wheel --exclude=.DS_Store --exclude=.svn --exclude=.gdb_history --exclude=build --exclude=\*.mode* --exclude=\*.pbxuser --exclude=\*.perspective -zchf launch-$VERSION.tar.gz launch-$VERSION && \
scp $TARBALL ainaz:web/nriley/software/
:
