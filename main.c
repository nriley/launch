/*
 launch - a smarter 'open' replacement
 Nicholas Riley <launchsw@sabi.net>

 Copyright (c) 2001-14, Nicholas Riley
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of this software nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
*/

#define BROKEN_AUTHORIZATION 1
#define kComponentSignatureString "launch"

#include <unistd.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <Carbon/Carbon.h>
#include <CoreServices/CoreServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>

#ifndef BROKEN_AUTHORIZATION
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#endif

const char *APP_NAME;

#define VERSION "1.2d1"

#define STRBUF_LEN 1024
#define ACTION_DEFAULT ACTION_OPEN

struct {
    OSType creator;
    CFStringRef bundleID, name;
    Boolean forceURLs;
    enum { ACTION_FIND, ACTION_FIND_ITEMS,
	   ACTION_OPEN, ACTION_OPEN_ITEMS, 
	   ACTION_INFO_ITEMS, ACTION_LAUNCH_URLS } action;
} OPTS = 
{
    kLSUnknownCreator, NULL, NULL, false,
    ACTION_DEFAULT
};

// equivalent to kLSLaunchDefaults, but we can modify individual flags later
#define DEFAULT_LAUNCH_FLAGS (kLSLaunchNoParams | kLSLaunchAsync)

LSApplicationParameters LPARAMS = {0, DEFAULT_LAUNCH_FLAGS, NULL, NULL, NULL, NULL, NULL};
CFArrayRef ITEMS = NULL;
FSRef APPLICATION;

char *TEMPFILE = NULL;

typedef struct {
    OSStatus status;
    const char *desc;
} errRec, errList[];

static errList ERRS = {
    // Launch Services errors
    { kLSAppInTrashErr, "application is in the Trash" },
    { kLSExecutableIncorrectFormat, "executable is unsupported on this processor architecture" },
    { kLSUnknownErr, "unknown Launch Services error" },
    { kLSNotAnApplicationErr, "item is not an application" },
    { kLSDataUnavailableErr, "item metadata is unavailable" },
    { kLSApplicationNotFoundErr, "application not found" },
    { kLSUnknownTypeErr, "cannot determine item kind" },
    { kLSLaunchInProgressErr, "application is being opened; please try again after the application is open" },
    { kLSServerCommunicationErr, "unable to connect to Launch Services.\nAre you logged in?" },
    { kLSIncompatibleSystemVersionErr, "application is incompatible with this version of OS X" },
    { kLSNoLaunchPermissionErr, "no permission to launch this application", },
    { kLSNoExecutableErr, "application package contains no executable, or an unusable executable" },
    { kLSNoClassicEnvironmentErr, "Classic environment required but not available" },
    { kLSMultipleSessionsNotSupportedErr, "unable to launch multiple instances of application" },
#ifndef BROKEN_AUTHORIZATION
    // Security framework errors
    { errAuthorizationDenied, "authorization denied" },
    { errAuthorizationCanceled, "authentication was cancelled" },
#endif
    // Internet Config errors
    { icPrefNotFoundErr, "no helper application is defined for the URL's scheme" },
    { icNoURLErr, "not a URL" },
    { icInternalErr, "internal Internet Config error" },
    // Misc. errors
    { nsvErr, "the volume cannot be found (buggy filesystem?)" },
    { procNotFound, "unable to connect to system service.\nAre you logged in?" },
    { kCGErrorIllegalArgument, "window server error.\nAre you logged in?" },
    { fnfErr, "file not found" },
    { eofErr, "data not found" },
    { 0, NULL }
};

void usage() {
    fprintf(stderr, "usage: %s [-npswbmhLU] [-c creator] [-i bundleID] [-u URL] [-a name|path] [-o argument] [item ...] [-]\n"
                    "   or: %s [-npflswbmhLU] "
                    "[-o argument] "
                    "item ...\n", APP_NAME, APP_NAME);
    fprintf(stderr,
        "  -n            print matching paths/URLs instead of opening them\n"
        "  -p            ask application(s) to print document(s)\n"
	"  -f            display information about item(s)\n"
        "  -l            launch URLs (e.g. treat http:// URLs as Web sites, not WebDAV)\n"
#ifndef BROKEN_AUTHORIZATION
        "  -s            launch target(s) as superuser (authenticating if needed)\n"
#endif
        "  -w            wait for application to finish opening before exiting\n"
        "  -b            launch application in the background\n"
        "  -m            launch application again, even if already running\n"
        "  -h            hide application once it's finished opening\n"
	"  -L            suppress normal opening behavior (e.g. untitled window)\n"
	"  -U            interpret items as URLs, even if same-named files exist\n"
        "  -c creator    match application by four-character creator code ('ToyS')\n"
        "  -i bundle ID  match application by bundle identifier (com.apple.scripteditor)\n"
        "  -u URL        open application at file:// URL (NOT RECOMMENDED for scripts)\n"
        "  -a name|path  match application by name/path (NOT RECOMMENDED, very fragile)\n"
        "  -o argument   pass argument to application (may be specified more than once)\n"
        "'document' may be a file, folder, or disk - whatever the application can open.\n"
        "'item' may be a file, folder, disk, or URL.\n\n");
    fprintf(stderr, "launch "VERSION" (c) 2001-14 Nicholas Riley <http://sabi.net/nriley/software/>.\n"
	            "Please send bugs, suggestions, etc. to <launchsw@sabi.net>.\n");

    exit(1);
}

char * const FAILED_STR = "(unable to retrieve error message)";

char *osstatusstr(OSStatus err) {
    errRec *rec;
    const char *errDesc = "unknown error";
    static char *str = NULL;
    size_t size;
    if (str != NULL && str != FAILED_STR) free(str);
    for (rec = &(ERRS[0]) ; rec->status != 0 ; rec++)
        if (rec->status == err) {
            errDesc = rec->desc;
            break;
        }
    size = (strlen(errDesc) + 10) * sizeof(char);
    str = (char *)malloc(size);
    if (str != NULL)
        snprintf(str, size, "%s (%ld)", errDesc, err);
    else
        str = FAILED_STR;
    return str;
}

char *cferrorstr(CFErrorRef error) {
    CFStringRef string = CFErrorCopyFailureReason(error);
    if (string == NULL)
        string = CFErrorCopyDescription(error); // will never return NULL
    static char *str = NULL;
    if (str != NULL && str != FAILED_STR) free(str);
    CFIndex size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(string), kCFStringEncodingUTF8);
    str = malloc(size);
    if (str == NULL || !CFStringGetCString(string, str, size, kCFStringEncodingUTF8))
        str = FAILED_STR;
    CFRelease(string);
    return str;
}

void osstatusexit(OSStatus err, const char *fmt, ...) {
    va_list ap;
    const char *errDesc = osstatusstr(err);
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", APP_NAME);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", errDesc);
    exit(1);
}

void errexit(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", APP_NAME);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    exit(1);
}

#ifndef BROKEN_AUTHORIZATION

Boolean authenticated(AuthorizationItem item, AuthorizationRef *pAuthRef) {
    AuthorizationRights rights;
    AuthorizationRights *authorizedRights;
    AuthorizationFlags flags;
    OSStatus err;

    // Create an AuthorizationRef yet with the kAuthorizationFlagDefaults
    // flags to get the user's current authorization rights.
    rights.count = 0;
    rights.items = NULL;
    
    flags = kAuthorizationFlagDefaults;

    err = AuthorizationCreate(&rights,
        kAuthorizationEmptyEnvironment, flags,
        pAuthRef);
        
    rights.count = 1;
    rights.items = &item;
    
    flags = kAuthorizationFlagExtendRights;
    
    // don't ask for a password, just return failure if no rights
    err = AuthorizationCopyRights(*pAuthRef, &rights,
        kAuthorizationEmptyEnvironment, flags, &authorizedRights);

    switch (err) {
    case errAuthorizationSuccess:
        // we don't need these items, and they need to be disposed of
        AuthorizationFreeItemSet(authorizedRights);
        return true;
    case errAuthorizationInteractionNotAllowed:
        return false;
    default:
        osstatusexit(err, "unable to determine authentication status");
    }
    return false; // to satisfy compiler
}

void authenticate(AuthorizationItem item, AuthorizationRef authorizationRef) {
    AuthorizationRights rights = {1, &item};
    AuthorizationRights *authorizedRights;
    AuthorizationFlags flags;
    OSStatus err;

    flags = kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights;

    // Here, since we've specified kAuthorizationFlagExtendRights and
    // have also specified kAuthorizationFlagInteractionAllowed, if the
    // user isn't currently authorized to execute tools as root 
    // (kAuthorizationRightExecute), they will be asked for their password. 
    // The err return value will indicate authorization success or failure.
    err = AuthorizationCopyRights(authorizationRef,&rights,
                        kAuthorizationEmptyEnvironment,
                        flags,&authorizedRights);
    
    if (errAuthorizationSuccess == err)
        AuthorizationFreeItemSet(authorizedRights);
    else
        osstatusexit(err, "unable to authenticate");
}
#endif

CFURLRef normalizedURLFromString(CFStringRef str) {
    CFURLRef url = CFURLCreateWithString(NULL, str, NULL);
    if (url != NULL) {
        CFURLRef absURL = CFURLCopyAbsoluteURL(url);
        CFRelease(url);
        url = NULL;
        if (absURL != NULL) {
            CFStringRef scheme = CFURLCopyScheme(absURL);
            url = absURL;
            if (scheme == NULL) {
                CFRelease(url);
                url = NULL;
            } else {
	        CFRelease(scheme);
	    }
        }
    }
    return url;
}

CFURLRef normalizedURLFromPrefixSlack(CFStringRef prefix, CFStringRef slackStr) {
    CFStringRef str = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@%@"),
                                               prefix, slackStr);
    CFURLRef normalizedURL = normalizedURLFromString(str);
    CFRelease(str);
    return normalizedURL;
}

char *tempFile(int *fd) {
    char *tmpDir = getenv("TMPDIR");
    const char * const tempTemplate = "/launch-stationery-XXXXXXXX";
    char *tempPath;
    OSStatus err;
    FSRef fsr;
    FSCatalogInfo catalogInfo;
    FileInfo *fInfo;

    // create temporary file
    if (tmpDir == NULL) tmpDir = "/tmp";
    tempPath = (char *)malloc(strlen(tmpDir) + strlen(tempTemplate) + 1);
    if (tempPath == NULL) errexit("can't allocate memory");
    strcpy(tempPath, tmpDir);
    strcat(tempPath, tempTemplate);
    if ( (*fd = mkstemp(tempPath)) == -1)
        errexit("can't create temporary file '%s'", tempPath);
    // mark file as stationery
    err = FSPathMakeRef((UInt8 *)tempPath, &fsr, NULL);
    if (err != noErr) osstatusexit(err, "can't find '%s'", tempPath);
    err = FSGetCatalogInfo(&fsr, kFSCatInfoFinderInfo, &catalogInfo, NULL, NULL, NULL);
    if (err != noErr) osstatusexit(err, "can't get information for '%s'", tempPath);
    fInfo = (FileInfo *)&(catalogInfo.finderInfo);
    fInfo->finderFlags |= kIsStationery;
    err = FSSetCatalogInfo(&fsr, kFSCatInfoFinderInfo, &catalogInfo);
    if (err != noErr) osstatusexit(err, "can't set information for '%s'", tempPath);
    
    return tempPath;
}

char *stdinAsTempFile() {
    unsigned char *buf;
    int bufsize;
    // Actual number of characters read, and therefore written.
    ssize_t charCount;
    int fd;
    struct stat stat_buf;
    char *tempFilePath;

    tempFilePath = tempFile(&fd);

    if (fstat(fd, &stat_buf) == -1)
        errexit("can't fstat temporary file '%s'", tempFilePath);

    bufsize = stat_buf.st_blksize;
    if ( (buf = (unsigned char *)malloc(bufsize * sizeof(unsigned char))) == NULL)
        errexit("can't allocate %ld bytes of buffer memory",
                bufsize * sizeof(unsigned char));

    // Loop until the end of the file.
    while (1) {
        // Read a block of input.
        charCount = read(STDIN_FILENO, buf, bufsize);
        if (charCount < 0) {
            errexit("can't read from standard input");
        }
        // End of this file?
        if (charCount == 0)
            break;
        // Write this block out.
        if (write(fd, buf, charCount) != charCount)
            errexit("error writing to file '%s'", tempFilePath);
    }
    free(buf);
    return tempFilePath;
}

void getargs(int argc, char * const argv[]) {
    extern char *optarg;
    extern int optind;
    int ch;
    OSStatus err;
    Boolean appSpecified = false;

    if (argc == 1) usage();
    
    while ( (ch = getopt(argc, argv, "npflswbmhLUc:i:u:a:o:")) != -1) {
        switch (ch) {
        case 'n':
            if (OPTS.action != ACTION_DEFAULT) errexit("choose only one of -n, -p, -f, -l options");
            OPTS.action = ACTION_FIND;
            break;
        case 'p':
            if (OPTS.action != ACTION_DEFAULT) errexit("choose only one of -n, -p, -f, -l options");
            OPTS.action = ACTION_OPEN;
            LPARAMS.flags |= kLSLaunchAndPrint;
            break;
        case 'f':
            if (OPTS.action != ACTION_DEFAULT) errexit("choose only one of -n, -p, -f, -l options");
            OPTS.action = ACTION_INFO_ITEMS;
            break;
        case 'l':
            if (OPTS.action != ACTION_DEFAULT) errexit("choose only one of -n, -p, -f, -l options");
            OPTS.action = ACTION_LAUNCH_URLS;
            break;
        case 's':
#ifdef BROKEN_AUTHORIZATION
	    errexit("-s option no longer functional after 10.1 Security Update, sorry");
#else
        {
            AuthorizationRef authRef;
            AuthorizationItem item = { kAuthorizationRightExecute, strlen(argv[0]), argv[0], 0 };
            OSStatus err;
            
            if (authenticated(item, &authRef)) {
                continue;
            }
            authenticate(item, authRef);
            err = AuthorizationExecuteWithPrivileges(authRef, argv[0], 0, &argv[1], NULL);
            if (err != noErr) osstatusexit(err, "unable to launch '%s' with superuser privileges", argv[0]);
            exit(0); // XXX exit status propagate?
        }
#endif
        case 'w': LPARAMS.flags ^= kLSLaunchAsync; break;      // synchronous
        case 'b': LPARAMS.flags |= kLSLaunchDontSwitch; break; // open in background
        case 'm': LPARAMS.flags |= kLSLaunchNewInstance; break;// open multiple
        case 'h': LPARAMS.flags |= kLSLaunchAndHide; break;    // hide once launched
	case 'L':
	{
	    OSStatus err;
	    LPARAMS.initialEvent = malloc(sizeof(AppleEvent));
	    err = AECreateAppleEvent(kASAppleScriptSuite, kASLaunchEvent, NULL, kAutoGenerateReturnID, kAnyTransactionID, LPARAMS.initialEvent);
	    if (err != noErr) osstatusexit(err, "unable to construct launch Apple Event", argv[0]);
	}
	case 'U': OPTS.forceURLs = true; break;
        case 'c':
            if (strlen(optarg) != 4) errexit("creator (argument of -c) must be four characters long");
            OPTS.creator = htonl(*(OSTypePtr)optarg);
	    appSpecified = true;
            break;
        case 'i':
            OPTS.bundleID = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
	    appSpecified = true;
            break;
        case 'a':
            err = FSPathMakeRef((UInt8 *)optarg, &APPLICATION, NULL);
            if (err == noErr) {
                LPARAMS.application = &APPLICATION;
            } else {
                OPTS.name = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
            }
            appSpecified = true;
            break;
	case 'u':
            { CFStringRef str = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
	      CFURLRef appURL = CFURLCreateWithString(NULL, str, NULL);
  	      if (appURL == NULL)
		  errexit("invalid URL (argument of -u)");
	      if (!CFURLGetFSRef(appURL, &APPLICATION))
                  errexit("can't find application (argument of -u)");
              CFRelease(appURL);
            }
            LPARAMS.application = &APPLICATION;
	    appSpecified = true;
	    break;
        case 'o':
            if (LPARAMS.argv == NULL)
                LPARAMS.argv = CFArrayCreateMutable(NULL, 0, NULL);
            CFArrayAppendValue((CFMutableArrayRef)LPARAMS.argv,
                               CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8));
            break;
        default: usage();
        }
    }
    
    argc -= optind;
    argv += optind;
    
    if ( (OPTS.action == ACTION_FIND || OPTS.action == ACTION_LAUNCH_URLS ||
	  OPTS.action == ACTION_INFO_ITEMS) && LPARAMS.flags != DEFAULT_LAUNCH_FLAGS)
        errexit("options -s, -b, -m, -h apply to application launch (not -n, -f or -l)");
    
    if (OPTS.creator == kLSUnknownCreator && OPTS.bundleID == NULL && OPTS.name == NULL) {
	if (argc == 0 && LPARAMS.application == NULL)
	    errexit("must specify an application by -u, or one or more of -c, -i, -a");
        if (!appSpecified) {
            if (OPTS.action == ACTION_FIND)
                OPTS.action = ACTION_FIND_ITEMS;
            if (OPTS.action == ACTION_OPEN)
                OPTS.action = ACTION_OPEN_ITEMS;
        }
    } else {
	if (LPARAMS.application != NULL)
	    errexit("application URL (argument of -u) incompatible with matching by -c, -i, -a");
    }

    if (OPTS.action == ACTION_LAUNCH_URLS && appSpecified)
        errexit("launching URLs with a given application is not supported; try without -l");

    if (OPTS.action == ACTION_INFO_ITEMS && appSpecified)
	errexit("can't get information (-f) on item(s) using an application (-u, -c, -i, -a)");

    if (argc == 0 && OPTS.action == ACTION_OPEN && LPARAMS.flags & kLSLaunchAndPrint)
        errexit("print option (-p) must be accompanied by document(s) to print");
    
    if (argc != 0) {
        int i;
        OSStatus err;
        CFStringRef argStr;
        CFURLRef itemURL;
        LSItemInfoRecord docInfo;

        if (OPTS.action == ACTION_FIND)
            errexit("application with documents only supported for open or print, not find");

        // handle document/item/URL arguments
        ITEMS = CFArrayCreateMutable(NULL, argc, NULL);
        for (i = 0 ; i < argc ; i++) {
            argStr = NULL;
            if (strcmp(argv[i], "-") == 0) {
                TEMPFILE = stdinAsTempFile();
                itemURL = CFURLCreateFromFileSystemRepresentation(NULL, (UInt8 *)TEMPFILE, strlen(TEMPFILE), false);
                LPARAMS.flags ^= kLSLaunchAsync;
            } else {
		struct stat stat_buf;
		if (!OPTS.forceURLs && stat(argv[i], &stat_buf) == 0) {
		    itemURL = NULL;
		} else {
		    argStr = CFStringCreateWithCString(NULL, argv[i], kCFStringEncodingUTF8);
		    // check for URLs
		    itemURL = normalizedURLFromString(argStr);
		    if (itemURL == NULL && OPTS.action == ACTION_LAUNCH_URLS) {
			// check for email addresses
			if (strchr(argv[i], '@') != NULL && strchr(argv[i], '/') == NULL)
			    itemURL = normalizedURLFromPrefixSlack(CFSTR("mailto:"), argStr);
			// check for "slack" URLs
			if (itemURL == NULL && strchr(argv[i], '.') != NULL && strchr(argv[i], '/') != argv[i])
			    itemURL = normalizedURLFromPrefixSlack(CFSTR("http://"), argStr);
		    }
		}
                if (itemURL == NULL) {
                    // check for file paths
                    itemURL = CFURLCreateFromFileSystemRepresentation(NULL, (UInt8 *)argv[i], strlen(argv[i]), false);
                    err = LSCopyItemInfoForURL(itemURL, kLSRequestExtensionFlagsOnly, &docInfo);
                    if (err != noErr) osstatusexit(err, "unable to locate '%s'", argv[i]);
                }
            }
            CFArrayAppendValue((CFMutableArrayRef)ITEMS, itemURL);
            // don't CFRelease the itemURL because CFArray doesn't retain it by default
            if (argStr != NULL) CFRelease(argStr);
        }
    }
}

Boolean stringFromURLIsRemote(CFURLRef url, char *strBuffer) {
    CFStringRef scheme = CFURLCopyScheme(url);
    Boolean isRemote = !CFEqual(scheme, CFSTR("file"));
    CFRelease(scheme);
    
    strBuffer[0] = '\0';
    if (isRemote) {
        CFStringRef urlString = CFURLGetString(url);
	CFStringGetCString(urlString, strBuffer, STRBUF_LEN, kCFStringEncodingUTF8);
    } else {
	if (CFURLGetFileSystemRepresentation(url, false, (UInt8 *)strBuffer, STRBUF_LEN)) {
	    if (strBuffer[0] == '.' && strBuffer[1] == '/') {
		// remove the leading "./"
		char *fromBufPtr = strBuffer + 2;
		while (true) {
		    *strBuffer = *fromBufPtr;
		    if (*fromBufPtr == '\0') break;
		    strBuffer++;
		    fromBufPtr++;
		}
	    }
	} else {
	    strcpy(strBuffer, "[can't get path: CFURLGetFileSystemRepresentation failed]");
	}
    }
    return isRemote;
}

void printPathFromURL(CFURLRef url, FILE *stream) {
    static char strBuffer[STRBUF_LEN];
    check(url != NULL && stream != NULL);
    stringFromURLIsRemote(url, strBuffer);
    fprintf(stream, "%s\n", strBuffer);
}

void printDateTime(const char *label, UTCDateTime *utcTime, const char *postLabel, Boolean printIfEmpty) {
    static CFDateFormatterRef formatter = NULL;
    static char strBuffer[STRBUF_LEN];
    if (formatter == NULL) {
	formatter = CFDateFormatterCreate(NULL, CFLocaleCopyCurrent(), kCFDateFormatterShortStyle, kCFDateFormatterMediumStyle);
    }
    CFAbsoluteTime absoluteTime;
    OSStatus err;

    err = UCConvertUTCDateTimeToCFAbsoluteTime(utcTime, &absoluteTime);
    if (err == kUTCUnderflowErr) {
        if (printIfEmpty) printf("\t%s: (not set)\n", label);
        return;
    }
    if (err != noErr) osstatusexit(err, "unable to convert UTC %s time", label);

    CFStringRef dateTimeString = CFDateFormatterCreateStringWithAbsoluteTime(NULL, formatter, absoluteTime);
    CFStringGetCString(dateTimeString, strBuffer, STRBUF_LEN, kCFStringEncodingUTF8);
    
    printf("\t%s: %s%s\n", label, strBuffer, postLabel);
}

#define DFORMAT(SIZE) ((float)(SIZE) / 1024.)

void printSizes(const char *label, UInt64 logicalSize, UInt64 physicalSize, Boolean printIfZero) {
    UInt32 bigSize = physicalSize >> 32, littleSize = physicalSize;
    if (!printIfZero && bigSize == 0 && littleSize == 0) return;
    printf("\t%s: ", label);
    if (bigSize == 0) {
        if (littleSize == 0) {
            printf("zero bytes on disk (zero bytes used)\n"); return;
        } else if (littleSize < 1024) printf("%lu bytes", littleSize);
        else {
            UInt32 adjSize = littleSize >> 10;
            if (adjSize < 1024) printf("%.1f KB", DFORMAT(littleSize));
            else {
                adjSize >>= 10; littleSize >>= 10;
                if (adjSize < 1024) printf("%.2f MB", DFORMAT(littleSize));
                else {
                    adjSize >>= 10; littleSize >>= 10;
                    printf("%.2f GB", DFORMAT(littleSize));
                }
            }
        }
    } else {
        if (bigSize < 256) printf("%lu GB", bigSize);
        else {
            bigSize >>= 2;
            printf("%lu TB", bigSize);
        }
    }
    printf(" on disk (%llu bytes used)\n", logicalSize);
        
}

void printMoreInfoForRef(FSRef fsr) {
    OSStatus err;
    FSCatalogInfo fscInfo;

    err = FSGetCatalogInfo(&fsr, kFSCatInfoNodeFlags | kFSCatInfoAllDates | kFSCatInfoDataSizes | kFSCatInfoRsrcSizes | kFSCatInfoValence, &fscInfo, NULL, NULL, NULL);
    if (err != noErr) osstatusexit(err, "unable to get catalog information for file");

    if (fscInfo.nodeFlags & kFSNodeIsDirectoryMask) {
        printf("\tcontents: ");
	switch (fscInfo.valence) {
	case 0: printf("zero items\n"); break;
	case 1: printf("1 item\n"); break;
	default: printf("%lu items\n", fscInfo.valence);
	}
    } else {
        printSizes("data fork size", fscInfo.dataLogicalSize, fscInfo.dataPhysicalSize, true);
        printSizes("rsrc fork size", fscInfo.rsrcLogicalSize, fscInfo.rsrcPhysicalSize, false);
    }

    if (fscInfo.nodeFlags & (kFSNodeLockedMask | kFSNodeForkOpenMask)) {
        printf("\tstatus:");
        if (fscInfo.nodeFlags & kFSNodeLockedMask) {
            if (fscInfo.nodeFlags & kFSNodeForkOpenMask) printf(" in use,");
            printf(" locked");
        } else {
            printf(" in use");
        }
        printf("\n");
    }
    
    printDateTime("created", &fscInfo.createDate, "", true);
    printDateTime("modified", &fscInfo.contentModDate, "", true);
    printDateTime("accessed", &fscInfo.accessDate, " [only updated by OS X]", false);
    printDateTime("backed up", &fscInfo.backupDate, "", false);
}

const char *utf8StringFromCFStringRef(CFStringRef cfStr) {
    static char tmpBuffer[STRBUF_LEN];
    CFStringGetCString(cfStr, tmpBuffer, STRBUF_LEN, kCFStringEncodingUTF8);
    return tmpBuffer;
}

const char *utf8StringFromOSType(OSType osType) {
    osType = ntohl(osType);
    CFStringRef typeStr = CFStringCreateWithBytes(NULL, (UInt8 *)&osType, 4, CFStringGetSystemEncoding(), false);
    if (typeStr == NULL) {
	// punt to displaying verbatim
	static char tmpBuffer[5];
	tmpBuffer[4] = '\0';
	strncpy(tmpBuffer, (const char *)&osType, 4);
	return tmpBuffer;
    }
    const char *buffer = utf8StringFromCFStringRef(typeStr);
    CFRelease(typeStr);
    return buffer;
}

// based on Apple's "CheckExecutableArchitecture" sample code

#define MAX_HEADER_BYTES 512

void swapHeader(uint8_t *bytes, ssize_t length) {
    for (ssize_t i = 0 ; i < length ; i += 4)
        *(uint32_t *)(bytes + i) = OSSwapInt32(*(uint32_t *)(bytes + i));
}

void printExecutableArchitectures(CFURLRef url, bool printOnFailure) {
    uint8_t path[PATH_MAX];
    if (printOnFailure)
        printf("\tarchitecture: ");
        
    if (!CFURLGetFileSystemRepresentation(url, true, path, PATH_MAX)) {
        if (printOnFailure) printf("(can't get executable)\n");
        return;
    }
    
    int fd = open((const char *)path, O_RDONLY, 0777);
    if (fd <= 0) {
        if (printOnFailure) printf("(can't read)\n");
        return;
    }
    
    uint8_t bytes[MAX_HEADER_BYTES];
    ssize_t length = read(fd, bytes, MAX_HEADER_BYTES);
    close(fd);

    if (length < sizeof(struct mach_header_64)) {
        if (printOnFailure) printf("(can't read Mach-O header)\n");
        return;
    }

    // Look for any of the six magic numbers relevant to Mach-O executables, and swap the header if necessary.
    uint32_t num_fat = 0, magic = *((uint32_t *)bytes);
    uint32_t max_fat = (length - sizeof(struct fat_header)) / sizeof(struct fat_arch);
    struct fat_arch one_fat = {0}, *fat;
    if (MH_MAGIC == magic || MH_CIGAM == magic) {
        struct mach_header *mh = (struct mach_header *)bytes;
        if (MH_CIGAM == magic) swapHeader(bytes, length);
        one_fat.cputype = mh->cputype;
        one_fat.cpusubtype = mh->cpusubtype;
        fat = &one_fat;
        num_fat = 1;
    } else if (MH_MAGIC_64 == magic || MH_CIGAM_64 == magic) {
        struct mach_header_64 *mh = (struct mach_header_64 *)bytes;
        if (MH_CIGAM_64 == magic) swapHeader(bytes, length);
        one_fat.cputype = mh->cputype;
        one_fat.cpusubtype = mh->cpusubtype;
        fat = &one_fat;
        num_fat = 1;
    } else if (FAT_MAGIC == magic || FAT_CIGAM == magic) {
        fat = (struct fat_arch *)(bytes + sizeof(struct fat_header));
        if (FAT_CIGAM == magic) swapHeader(bytes, length);
        num_fat = ((struct fat_header *)bytes)->nfat_arch;
        if (num_fat > max_fat) num_fat = max_fat;
    }
    
    if (num_fat == 0) {
        if (printOnFailure) printf("(none found)\n");
        return;
    }
    
    if (!printOnFailure)
        printf("\tarchitecture: ");
        
    for (int i = 0 ; i < num_fat ; i++) {
        if (i != 0) printf(", ");
        const NXArchInfo *arch = NXGetArchInfoFromCpuType(fat[i].cputype, fat[i].cpusubtype);
        if (arch == NULL) {
            printf("unknown (cputype %d, subtype %d)", fat[i].cputype, fat[i].cpusubtype);
            continue;
        }
        printf("%s", arch->description);
    }
    printf("\n");
}

// 'context' is to match prototype for CFArrayApplierFunction, it's unused
void printInfoFromURL(CFURLRef url, void *context) {
    CFStringRef kind;
    static char strBuffer[STRBUF_LEN];
    
    check(url != NULL && context == NULL);

    if (stringFromURLIsRemote(url, strBuffer)) {
        printf("<%s>: URL\n", strBuffer);
	return;
    }
    
    static LSItemInfoRecord info;
    OSStatus err;
    if ( (err = LSCopyItemInfoForURL(url, kLSRequestAllInfo, &info)) != noErr)
	osstatusexit(err, "unable to get information about '%s'", strBuffer);
    
    printf("%s: ", strBuffer);
    
    // modifiers
    if (info.flags & kLSItemInfoIsInvisible) printf("invisible ");
    if (info.flags & kLSItemInfoAppIsScriptable) printf("scriptable ");
    if (info.flags & kLSItemInfoIsNativeApp) printf("OS X ");
    if (info.flags & kLSItemInfoIsClassicApp) printf("Classic ");
    
    // kind
    if (info.flags & kLSItemInfoIsVolume) printf("volume");
    else if (info.flags & kLSItemInfoIsApplication) printf("application ");
    else if (info.flags & kLSItemInfoIsPackage) printf("non-application ");
    else if (info.flags & kLSItemInfoIsContainer) printf("folder");
    else if (info.flags & kLSItemInfoIsAliasFile) printf("alias");
    else if (info.flags & kLSItemInfoIsSymlink) printf("symbolic link");
    else if (info.flags & kLSItemInfoIsPlainFile) printf("document");
    else printf("unknown file system entity");

    if (info.flags & kLSItemInfoIsPackage) printf("package ");

    if (info.flags & kLSItemInfoAppPrefersNative) printf("[Carbon, prefers native OS X]");
    else if (info.flags & kLSItemInfoAppPrefersClassic) printf("[Carbon, prefers Classic]");

    printf("\n");
    if (!(info.flags & kLSItemInfoIsContainer) || info.flags & kLSItemInfoIsPackage) {
	printf("\ttype: '%s'", utf8StringFromOSType(info.filetype));
	printf("\tcreator: '%s'\n", utf8StringFromOSType(info.creator));
    }

    CFStringRef bundleID = NULL;
    CFStringRef version = NULL;
    UInt32 intVersion = 0;
    FSRef fsr;
    Boolean haveFSRef = CFURLGetFSRef(url, &fsr);
    CFBundleRef bundle = NULL;
    
    if ((info.flags & kLSItemInfoIsPackage || info.flags & kLSItemInfoIsApplication) &&
	( (bundle = CFBundleCreate(NULL, url)) != NULL)) {
	bundleID = CFBundleGetIdentifier(bundle);
	if (bundleID != NULL) CFRetain(bundleID);
	// prefer a short version string, e.g. "1.0 Beta" instead of "51" for Safari
	version = CFBundleGetValueForInfoDictionaryKey(bundle, CFSTR("CFBundleShortVersionString"));
	if (version == NULL)
	    version = CFBundleGetValueForInfoDictionaryKey(bundle, kCFBundleVersionKey);
	if (version != NULL) {
	    CFRetain(version);
	    intVersion = CFBundleGetVersionNumber(bundle);
	}
	CFURLRef executable = CFBundleCopyExecutableURL(bundle);
	if (executable != NULL) {
	    printExecutableArchitectures(executable, true);
	    CFRelease(executable);
	}
	CFRelease(bundle);
    } else if (info.flags & kLSItemInfoIsPackage || !haveFSRef) {
	printf("\t[can't access package contents]\n");
    } else if (haveFSRef) {
	SInt16 resFork = FSOpenResFile(&fsr, fsRdPerm);
	CFPropertyListRef infoPlist = NULL;
	if ( (err = ResError()) == noErr) {
	    Handle h = Get1Resource('plst', 0);
	    if (h == NULL) {
		err = ResError();
		if (err != noErr && err != resNotFound)
		    osstatusexit(err, "unable to read 'plst' 0 resource");
	    } else {
		CFDataRef plstData = CFDataCreate(NULL, (UInt8 *)*h, GetHandleSize(h));
		CFStringRef error = NULL;
		infoPlist = CFPropertyListCreateFromXMLData(NULL, plstData, kCFPropertyListImmutable, &error);
		if (plstData != NULL) CFRelease(plstData);
		if (infoPlist == NULL) {
		    printf("\t['plst' 0 resource invalid: %s]\n", utf8StringFromCFStringRef(error));
		    CFRelease(error);
		}
	    }
	}
	if (infoPlist == NULL) {
	    // this function should handle the 'plst' 0 case too, but it doesn't provide error messages; however, it handles the case of an unbundled Mach-O binary, so it is useful as a fallback
	    infoPlist = CFBundleCopyInfoDictionaryForURL(url);
	    if (infoPlist == NULL && info.flags & kLSItemInfoIsApplication && resFork == -1)
		printf("\t[can't open resource fork: %s]\n", osstatusstr(err));
	}
	if (infoPlist != NULL) {
	    // mimic CFBundle logic above
	    bundleID = CFDictionaryGetValue(infoPlist, kCFBundleIdentifierKey);
	    if (bundleID != NULL) CFRetain(bundleID);
	    version = CFDictionaryGetValue(infoPlist, CFSTR("CFBundleShortVersionString"));
	    if (version == NULL)
		version = CFDictionaryGetValue(infoPlist, kCFBundleVersionKey);
	    if (version != NULL) CFRetain(version);
	    CFRelease(infoPlist);
	}
	if (resFork != -1) {
	    VersRecHndl vers = (VersRecHndl)Get1Resource('vers', 1);
	    if (vers == NULL) {
		err = ResError();
		if (err != noErr && err != resNotFound)
		    osstatusexit(err, "unable to read 'vers' 1 resource");
	    } else {
		if (version == NULL) { // prefer 'plst' version
		    version = CFStringCreateWithPascalString(NULL, vers[0]->shortVersion, CFStringGetSystemEncoding()); // XXX use country code instead?
		}
		intVersion = ((NumVersionVariant)vers[0]->numericVersion).whole;
	    }
	    CloseResFile(resFork);
	}
	printExecutableArchitectures(url, false);
    }

    if (bundleID != NULL) {
	printf("\tbundle ID: %s\n", utf8StringFromCFStringRef(bundleID));
	CFRelease(bundleID);
    }
    if (version != NULL) {
	printf("\tversion: %s", utf8StringFromCFStringRef(version));
	if (intVersion != 0) printf(" [0x%lx = %lu]", intVersion, intVersion);
	putchar('\n');
	CFRelease(version);
    }

    // kind string
    err = LSCopyKindStringForURL(url, &kind);
    if (err != noErr) osstatusexit(err, "unable to get kind of '%s'", strBuffer);
    printf("\tkind: %s\n", utf8StringFromCFStringRef(kind));
    CFRelease(kind);
    
    if (haveFSRef) {
	// content type identifier (UTI)
	err = LSCopyItemAttribute(&fsr, kLSRolesAll, kLSItemContentType, (CFTypeRef *)&kind);
	if (err == noErr) {
	    printf("\tcontent type ID: %s\n", utf8StringFromCFStringRef(kind));
	    CFRelease(kind);
	}
	printMoreInfoForRef(fsr);
    }

    // alias target (note: may modify url)
    if (info.flags & kLSItemInfoIsAliasFile && haveFSRef) {
        CFErrorRef error;
        CFDataRef bookmarkData = CFURLCreateBookmarkDataFromFile(NULL, url, &error);
        if (bookmarkData == NULL) {
            printf("\t[can't decode alias: %s]\n", cferrorstr(error));
        } else {
            url = CFURLCreateByResolvingBookmarkData(NULL, bookmarkData, kCFBookmarkResolutionWithoutUIMask | kCFBookmarkResolutionWithoutUIMask, NULL, NULL, NULL, &error);
            if (url == NULL) {
                printf("\t[can't resolve alias: %s]\n", cferrorstr(error));
            } else {
		printf("\ttarget: ");
		printPathFromURL(url, stdout);
		CFRelease(url);
            }
            CFRelease(bookmarkData);
        }
    }
}


void launchURL(CFURLRef url, ICInstance icInst) {
    CFStringRef urlStr = CFURLGetString(url);
    static char strBuffer[STRBUF_LEN];
    long strStart, strEnd;
    OSStatus err;

    strBuffer[0] = '\0';
    CFStringGetCString(urlStr, strBuffer, STRBUF_LEN, CFStringGetSystemEncoding()); // XXX no idea what encoding ICLaunchURL is supposed to take; leave as is for now
    strStart = 0;
    strEnd = strlen(strBuffer);
    err = ICLaunchURL(icInst, "\p", strBuffer, strEnd, &strStart, &strEnd);
    if (err != noErr) {
        fprintf(stderr, "%s: unable to launch URL <%s>: %s\n", APP_NAME, strBuffer, osstatusstr(err));
    }
    
    CFRelease(urlStr);
}

OSStatus openItems(void) {
    if (ITEMS == NULL)
        ITEMS = CFArrayCreate(NULL, NULL, 0, NULL);
    // CFShow(LPARAMS.argv);
    return LSOpenURLsWithRole(ITEMS, kLSRolesAll, NULL, &LPARAMS, NULL, 0);
}

void background() {
    if (fork() > 1)
        exit(0);
    
    int fd;
    
    if ( (fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
    }
}

int main (int argc, char * const argv[]) {
    OSStatus err;
    
    APP_NAME = argv[0];
    getargs(argc, argv);

    if (OPTS.action == ACTION_FIND || OPTS.action == ACTION_OPEN) {
        if (LPARAMS.application != NULL) goto findOK; // already have an application FSRef
	err = LSFindApplicationForInfo(OPTS.creator, OPTS.bundleID, OPTS.name, &APPLICATION, NULL);
        LPARAMS.application = &APPLICATION;
        
	if (err != noErr) {
	    if (OPTS.name != NULL && !CFStringHasSuffix(OPTS.name, CFSTR(".app"))) {
		OPTS.name = CFStringCreateMutableCopy(NULL, CFStringGetLength(OPTS.name) + 4, OPTS.name);
		CFStringAppend((CFMutableStringRef)OPTS.name, CFSTR(".app"));
		err = LSFindApplicationForInfo(OPTS.creator, OPTS.bundleID, OPTS.name, &APPLICATION, NULL);
		if (err == noErr) goto findOK;
	    }
	    osstatusexit(err, "can't locate application");
	}
        findOK: ;
    }
    
    switch (OPTS.action) {
    case ACTION_FIND:
	printPathFromURL(CFURLCreateFromFSRef(NULL, LPARAMS.application), stdout);
	break;
    case ACTION_OPEN:
	err = openItems();
	if (err != noErr) osstatusexit(err, "can't open application");
	break;
    case ACTION_FIND_ITEMS:
        CFArrayApplyFunction(ITEMS, CFRangeMake(0, CFArrayGetCount(ITEMS)),
			     (CFArrayApplierFunction) printPathFromURL, stdout);
	break;
    case ACTION_OPEN_ITEMS:
	err = openItems();
	if (err != noErr) osstatusexit(err, "can't open items");
	break;
    case ACTION_INFO_ITEMS:
        CFArrayApplyFunction(ITEMS, CFRangeMake(0, CFArrayGetCount(ITEMS)),
			     (CFArrayApplierFunction) printInfoFromURL, NULL);
	break;
    case ACTION_LAUNCH_URLS:
    {
        ICInstance icInst;
        err = ICStart(&icInst, '\?\?\?\?'); // in case GCC trigraph handling is enabled
        if (err != noErr) osstatusexit(err, "can't initialize Internet Config", argv[1]);
        CFArrayApplyFunction(ITEMS, CFRangeMake(0, CFArrayGetCount(ITEMS)),
                             (CFArrayApplierFunction) launchURL, icInst);
        ICStop(icInst);
        break;
    }
    }

    if (TEMPFILE != NULL) {
        // the application may take a while to finish opening the temporary file
        background();
        sleep(60);
        unlink(TEMPFILE);
    }

    return 0;
}
