/*
  * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
  *
  * @APPLE_LICENSE_HEADER_START@
  *
  * The contents of this file constitute Original Code as defined in and
  * are subject to the Apple Public Source License Version 1.1 (the
  * "License").  You may not use this file except in compliance with the
  * License.  Please obtain a copy of the License at
  * http://www.apple.com/publicsource and read it before using this file.
  *
  * This Original Code and all software distributed under the License are
  * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
  * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
  * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
  * License for the specific language governing rights and limitations
  * under the License.
  *
  * @APPLE_LICENSE_HEADER_END@
  */
/*
  * Shantonu Sen <ssen@apple.com>
  * openUp.c - program to set the "first-open-window" field of a volume
  *
  * Get the directory ID for the first argument, and set it as word 2
  * of the Finder Info fields for the volume it lives on
  *
  * cc -o openUp openUp.c
  * Usage: openUp /Volumes/Foo/OpenMe/
  *
  */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/mount.h>

struct directoryinfo {
	unsigned long length;
	u_int32_t dirid;
};

struct volumeinfo {
	unsigned long length;
	u_int32_t  finderinfo[8];
};

const char *APP_NAME;

void errnoexit(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", APP_NAME);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, " (%s)\n", strerror(errno));
	exit(1);
}

int main(int argc, char *argv[]) {
	
	char *path = NULL;
	struct attrlist alist;
	struct directoryinfo dirinfo;
	struct volumeinfo volinfo;
	struct statfs sfs;
	int err;
	
	APP_NAME = argv[0];
	
	if (argc != 2) {
		fprintf(stderr, "usage: %s <path to folder whose window should open when volume is mounted>\n",
				APP_NAME);
		exit(1);
	}
	
	path = argv[1];
	
	bzero(&alist, sizeof(alist));
	alist.bitmapcount = 5;
	alist.commonattr = ATTR_CMN_OBJID;
	
	if (getattrlist(path, &alist, &dirinfo, sizeof(dirinfo), 0))
		errnoexit("getattrlist on path failed");
	
	printf("directory id: %lu\n", dirinfo.dirid);
	
	if (statfs(path, &sfs))
		errnoexit("statfs failed");
	
	printf("mountpoint: %s\n", sfs.f_mntonname);
	
	alist.commonattr = ATTR_CMN_FNDRINFO;
	alist.volattr = ATTR_VOL_INFO;
	
	if (getattrlist(sfs.f_mntonname, &alist, &volinfo, sizeof(volinfo), 0))
		errnoexit("getattrlist on mount point failed");
	volinfo.finderinfo[2] = dirinfo.dirid;
	if (setattrlist(sfs.f_mntonname, &alist, volinfo.finderinfo,
		sizeof(volinfo.finderinfo), 0))
		errnoexit("setattrlist on mount point failed");
	
	return 0;

}

