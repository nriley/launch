#!/bin/sh

set -x -v

cd launch && \
find . -name \*~ -exec rm '{}' \; && \
pbxbuild && \ 
SetFile -c 'R*ch' -t 'TEXT' README VERSION && \
strip build/launch && \
sudo /usr/bin/install -c build/launch /usr/local/bin && \
rm -rf build/launch.build build/intermediates build/.gdb_history && \
VERSION=`cat VERSION` TARBALL="launch-$VERSION.tar.gz" && \
DMG="launch-$VERSION.dmg" VOL="launch $VERSION" MOUNTPOINT="/Volumes/$VOL" && \
cd .. && \
rm -f launch-$VERSION $TARBALL $DMG && \
ln -s launch launch-$VERSION && \
tar --exclude=.DS_Store -zchf launch-$VERSION.tar.gz launch-$VERSION && \
#hdiutil create $DMG -megabytes 5 -ov -type UDIF && \
#DISK=`hdid $DMG | sed -ne ' /Apple_partition_scheme/ s|^/dev/\([^ ]*\).*$|\1|p'` && \
#newfs_hfs -v "$VOL" /dev/r${DISK}s2 && \
#hdiutil eject $DISK && \
#hdid $DMG && \
#ditto -rsrc launch "$MOUNTPOINT" && \
#ditto -rsrc "InstallAnywhere/launch_Web_Installers/InstData/MacOSX/Install launch $VERSION.sit" "/Volumes/launch $VERSION" && \
#launch "$MOUNTPOINT/Install launch $VERSION.sit" && \
#./openUp "$MOUNTPOINT" && \
#sleep 2 && \
## hdiutil eject $DISK && \ # this doesn't work
#osascript -e "tell application \"Finder\" to eject disk \"$VOL\"" && \
#hdiutil convert $DMG -format UDZO -o z$DMG && \
#mv z$DMG $DMG && \
scp $TARBALL ainaz:web/nriley/software/ #$DMG 