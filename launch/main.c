/*
 launch - a smarter 'open' replacement
 Nicholas Riley <launchsw@sabi.net>

 Copyright (c) 2002, Nicholas Riley
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of this software nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
*/

/* To do/think about:

- Do we need to assume -b if -h?  Hiding the foreground app just makes
it flash (only if Cocoa?)

- Does -X work at all?  What does it return if it fails?

- Launching as root: use authentication framework - doesn't work.

- launch URL with specified URL handler (done, except for IC)

- launch apps by IC protocol handler (esp. editor)

Thanks to:

- Nat Irons, for encouragement and suggestions

- Brian Hill, for the great Security.framework tutorial and sample code

*/

#define DEBUG 1
#define BROKEN_AUTHORIZATION 1
#define BROKEN_LAUNCHNEWINSTANCE 1
#define kComponentSignatureString "launch"

#include <unistd.h>
#include <sys/stat.h>
#include <Carbon/Carbon.h>
#include <CoreServices/CoreServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>

#ifndef BROKEN_AUTHORIZATION
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#endif

const char *APP_NAME;

#define VERSION "1.0b1"

#define STRBUF_LEN 1024
#define ACTION_DEFAULT ACTION_OPEN

struct {
    OSType creator;
    CFStringRef bundleID, name;
    enum { ACTION_FIND, ACTION_FIND_ITEMS,
	   ACTION_OPEN, ACTION_OPEN_ITEMS, 
	   ACTION_INFO_ITEMS, ACTION_LAUNCH_URLS } action;
} OPTS = 
{
    kLSUnknownCreator, NULL, NULL,
    ACTION_DEFAULT
};

#define DEFAULT_LAUNCH_FLAGS (kLSLaunchNoParams | kLSLaunchStartClassic | kLSLaunchAsync)

LSLaunchURLSpec LSPEC = {NULL, NULL, NULL, DEFAULT_LAUNCH_FLAGS, NULL};

char *TEMPFILE = NULL;

typedef struct {
    OSStatus status;
    const char *desc;
} errRec, errList[];

static errList ERRS = {
    // Launch Services errors
    { kLSUnknownErr, "unknown Launch Services error" },
    { kLSApplicationNotFoundErr, "application not found" },
    { kLSLaunchInProgressErr, "application is being opened; please try again after the application is open" },
    { kLSNotRegisteredErr, "application not registered in Launch Services database" },
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
    { procNotFound, "unable to connect to system service.\nAre you logged in?" },
    { 1001, "SystemConfiguration nonspecific failure.\nAre you logged in?" },
    { fnfErr, "file not found" },
    { 0, NULL }
};

void usage() {
    fprintf(stderr, "usage: %s [-npswbmhCX] [-c creator] [-i bundleID] [-u URL] [-a name] [item ...] [-]\n"
                    "   or: %s [-npflswbmhCX] item ...\n", APP_NAME, APP_NAME);
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
#ifndef BROKEN_LAUNCHNEWINSTANCE
        "  -m            launch application again, even if already running\n"
#endif
        "  -h            hide application once it's finished opening\n"
        "  -C            force CFM/PEF Carbon application to launch in Classic\n"
        "  -X            don't start Classic for this app if Classic isn't running\n"
        "  -c creator    match application by four-character creator code ('ToyS')\n"
        "  -i bundle ID  match application by bundle identifier (com.apple.scripteditor)\n"
        "  -u URL        open application at file:// URL (NOT RECOMMENDED for scripts)\n"
        "  -a name       match application by name (NOT RECOMMENDED, very fragile)\n"
        "'document' may be a file, folder, or disk - whatever the application can open.\n"
        "'item' may be a file, folder, disk, or URL.\n\n");
    fprintf(stderr, "launch "VERSION" (c) 2001-02 Nicholas Riley <http://web.sabi.net/nriley/software/>.\n"
	            "Please send bugs, suggestions, etc. to <launchsw@sabi.net>.\n");

    exit(1);
}

char *osstatusstr(OSStatus err) {
    errRec *rec;
    const char *errDesc = "unknown error";
    char * const failedStr = "(unable to retrieve error message)";
    static char *str = NULL;
    size_t len;
    if (str != NULL && str != failedStr) free(str);
    for (rec = &(ERRS[0]) ; rec->status != 0 ; rec++)
        if (rec->status == err) {
            errDesc = rec->desc;
            break;
        }
    len = strlen(errDesc) + 10 * sizeof(char);
    str = (char *)malloc(len);
    if (str != NULL)
        snprintf(str, len, "%s (%ld)", errDesc, err);
    else
        str = failedStr;
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
    err = FSPathMakeRef(tempPath, &fsr, NULL);
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
    Boolean appSpecified = false;

    if (argc == 1) usage();
    
    while ( (ch = getopt(argc, argv, "npflswbmhCXc:i:u:a:")) != -1) {
        switch (ch) {
        case 'n':
            if (OPTS.action != ACTION_DEFAULT) errexit("choose only one of -n, -p, -f, -l options");
            OPTS.action = ACTION_FIND;
            break;
        case 'p':
            if (OPTS.action != ACTION_DEFAULT) errexit("choose only one of -n, -p, -f, -l options");
            OPTS.action = ACTION_OPEN;
            LSPEC.launchFlags |= kLSLaunchAndPrint;
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
        case 'w': LSPEC.launchFlags ^= kLSLaunchAsync; break;      // synchronous
        case 'b': LSPEC.launchFlags |= kLSLaunchDontSwitch; break; // open in background
#ifdef BROKEN_LAUNCHNEWINSTANCE
        case 'm': errexit("-m option not functional (LaunchServices bug?), sorry");
#else
        case 'm': LSPEC.launchFlags |= kLSLaunchNewInstance; break;// open multiple
#endif
        case 'h': LSPEC.launchFlags |= kLSLaunchAndHide; break;    // hide once launched
        case 'C': LSPEC.launchFlags |= kLSLaunchInClassic; break;  // force Classic
        case 'X': LSPEC.launchFlags ^= kLSLaunchStartClassic; break;// don't start Classic for app
        case 'c':
            if (strlen(optarg) != 4) errexit("creator (argument of -c) must be four characters long");
            OPTS.creator = *(OSTypePtr)optarg;
	    appSpecified = true;
            break;
        case 'i':
            OPTS.bundleID = CFStringCreateWithCString(NULL, optarg, CFStringGetSystemEncoding());
	    appSpecified = true;
            break;
        case 'a':
            OPTS.name = CFStringCreateWithCString(NULL, optarg, CFStringGetSystemEncoding());
	    appSpecified = true;
            break;
	case 'u':
            { CFStringRef str = CFStringCreateWithCString(NULL, optarg, CFStringGetSystemEncoding());
	      LSPEC.appURL = CFURLCreateWithString(NULL, str, NULL);
              if (str != NULL) CFRelease(str);
            }
	    if (LSPEC.appURL == NULL) {
		errexit("invalid URL (argument of -u)");
	    } else {
		CFURLRef absURL = CFURLCopyAbsoluteURL(LSPEC.appURL);
		CFRelease(LSPEC.appURL);
		LSPEC.appURL = NULL;
		if (absURL != NULL) {
		    CFStringRef scheme = CFURLCopyScheme(absURL);
		    LSPEC.appURL = absURL;
		    if (scheme == NULL || !CFEqual(scheme, CFSTR("file")))
			errexit("invalid file:// URL (argument of -u)");
		}
	    }
	    appSpecified = true;
	    break;
        default: usage();
        }
    }
    
    argc -= optind;
    argv += optind;
    
    if ( (OPTS.action == ACTION_FIND || OPTS.action == ACTION_LAUNCH_URLS ||
	  OPTS.action == ACTION_INFO_ITEMS) && LSPEC.launchFlags != DEFAULT_LAUNCH_FLAGS)
        errexit("options -s, -b, -m, -h, -C, -X apply to application launch (not -n, -f or -l)");
    
    if (OPTS.creator == kLSUnknownCreator && OPTS.bundleID == NULL && OPTS.name == NULL) {
	if (argc == 0 && LSPEC.appURL == NULL)
	    errexit("must specify an application by -u, or one or more of -c, -i, -a");
        if (!appSpecified) {
            if (OPTS.action == ACTION_FIND)
                OPTS.action = ACTION_FIND_ITEMS;
            if (OPTS.action == ACTION_OPEN)
                OPTS.action = ACTION_OPEN_ITEMS;
        }
    } else {
	if (LSPEC.appURL != NULL)
	    errexit("application URL (argument of -u) incompatible with matching by -c, -i, -a");
    }

    if (OPTS.action == ACTION_LAUNCH_URLS && appSpecified)
        errexit("launching URLs with a given application is not supported; try without -l");

    if (OPTS.action == ACTION_INFO_ITEMS && appSpecified)
	errexit("can't get information (-f) on item(s) using an application (-u, -c, -i, -a)");

    if (argc == 0 && OPTS.action == ACTION_OPEN && LSPEC.launchFlags & kLSLaunchAndPrint)
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
        LSPEC.itemURLs = CFArrayCreateMutable(NULL, argc, NULL);
        for (i = 0 ; i < argc ; i++) {
            argStr = NULL;
            if (strcmp(argv[i], "-") == 0) {
                TEMPFILE = stdinAsTempFile();
                itemURL = CFURLCreateFromFileSystemRepresentation(NULL, TEMPFILE, strlen(TEMPFILE), false);
                LSPEC.launchFlags ^= kLSLaunchAsync;
            } else {
                argStr = CFStringCreateWithCString(NULL, argv[i], CFStringGetSystemEncoding());
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
                if (itemURL == NULL) {
                    // check for file paths
                    itemURL = CFURLCreateWithFileSystemPath(NULL, argStr, kCFURLPOSIXPathStyle, false);
                    err = LSCopyItemInfoForURL(itemURL, kLSRequestExtensionFlagsOnly, &docInfo);
                    if (err != noErr) osstatusexit(err, "unable to locate '%s'", argv[i]);
                }
            }
            CFArrayAppendValue((CFMutableArrayRef)LSPEC.itemURLs, itemURL);
            // don't CFRelease the itemURL because CFArray doesn't retain it by default
            if (argStr != NULL) CFRelease(argStr);
        }
    }
}

// 'context' is to match prototype for CFArrayApplierFunction, it's unused
void printPathFromURL(CFURLRef url, void *context) {
    CFStringRef scheme, pathOrURL;
    static char strBuffer[STRBUF_LEN];
    
    check(url != NULL && context == NULL);

    scheme = CFURLCopyScheme(url);
    
    if (CFEqual(scheme, CFSTR("file")))
        pathOrURL = CFURLCopyFileSystemPath(url, kCFURLPOSIXPathStyle);
    else
        pathOrURL = CFURLGetString(url);

    strBuffer[0] = '\0';
    CFStringGetCString(pathOrURL, strBuffer, STRBUF_LEN, CFStringGetSystemEncoding()); // XXX buffer size issues?
    printf("%s\n", strBuffer);
    CFRelease(scheme);
    CFRelease(pathOrURL);
}

void printDateTime(const char *label, UTCDateTime *utcTime, const char *postLabel, Boolean printIfEmpty) {
    static Str255 dateStr, timeStr;
    LocalDateTime localTime;
    LongDateTime longTime;
    OSStatus err;

    err = ConvertUTCToLocalDateTime(utcTime, &localTime);
    if (err == kUTCUnderflowErr) {
        if (printIfEmpty) printf("\t%s: (not set)\n", label);
        return;
    }
    if (err != noErr) osstatusexit(err, "unable to convert UTC %s date to local", label);

    longTime = localTime.highSeconds;
    longTime <<= 32;
    longTime |= localTime.lowSeconds;

    // strings include trailing newlines; strip them.
    LongDateString(&longTime, shortDate, dateStr, nil); dateStr[dateStr[0] + 1] = '\0';
    LongTimeString(&longTime, true, timeStr, nil); timeStr[timeStr[0] + 1] = '\0';
    printf("\t%s: %s %s%s\n", label, dateStr + 1, timeStr + 1, postLabel);
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

void printMoreInfoFromURL(CFURLRef url) {
    FSRef fsr;
    OSStatus err;
    FSCatalogInfo fscInfo;

    if (!CFURLGetFSRef(url, &fsr)) return;
    err = FSGetCatalogInfo(&fsr, kFSCatInfoNodeFlags | kFSCatInfoAllDates | kFSCatInfoDataSizes | kFSCatInfoRsrcSizes | kFSCatInfoValence, &fscInfo, NULL, NULL, NULL);
    if (err != noErr) osstatusexit(err, "unable to get catalog information for file");

    if (fscInfo.nodeFlags & kFSNodeIsDirectoryMask) {
        printf("\tcontents: %lu item%s\n", fscInfo.valence, fscInfo.valence != 1 ? "s" : "");
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
    printDateTime("accessed", &fscInfo.accessDate, " [only updated by Mac OS X]", false);
    printDateTime("backed up", &fscInfo.backupDate, "", false);
}

// 'context' is to match prototype for CFArrayApplierFunction, it's unused
void printInfoFromURL(CFURLRef url, void *context) {
    CFStringRef scheme, pathOrURL, kind;
    Boolean isRemote;
    static char strBuffer[STRBUF_LEN], tmpBuffer[STRBUF_LEN];
    
    check(url != NULL && context == NULL);

    scheme = CFURLCopyScheme(url);
    
    isRemote = !CFEqual(scheme, CFSTR("file"));
    if (isRemote)
        pathOrURL = CFURLGetString(url);
    else
        pathOrURL = CFURLCopyFileSystemPath(url, kCFURLPOSIXPathStyle);

    strBuffer[0] = '\0';
    CFStringGetCString(pathOrURL, strBuffer, STRBUF_LEN, CFStringGetSystemEncoding()); // XXX buffer size issues?
    if (isRemote)
        printf("<%s>: URL\n", strBuffer);
    else {
        static LSItemInfoRecord info;
        OSStatus err = LSCopyItemInfoForURL(url, kLSRequestAllInfo, &info);
        if (err != noErr) osstatusexit(err, "unable to get information about '%s'", strBuffer);
        
        printf("%s: ", strBuffer);
        
        // modifiers
        if (info.flags & kLSItemInfoIsInvisible) printf("invisible ");
        if (info.flags & kLSItemInfoAppIsScriptable) printf("scriptable ");
        if (info.flags & kLSItemInfoIsNativeApp) printf("Mac OS X ");
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
            tmpBuffer[4] = '\0';
            strncpy(tmpBuffer, (char *)&info.filetype, 4); printf("\ttype: '%s'", tmpBuffer);
            strncpy(tmpBuffer, (char *)&info.creator, 4); printf("\tcreator: '%s'\n", tmpBuffer);
        }
        if (info.flags & kLSItemInfoIsPackage ||
        	info.flags & kLSItemInfoIsApplication && info.flags & kLSItemInfoIsNativeApp) {
        	// a package, or possibly a native app with a 'plst' resource
            CFBundleRef bundle = CFBundleCreate(NULL, url);
            CFStringRef bundleID;
            if (bundle == NULL) { // OS X bug causes this to fail when it shouldn't, so just note it, don't die
            	if (info.flags & kLSItemInfoIsApplication) printf("\t[can't access CFBundle for application]\n");
            } else {
                bundleID = CFBundleGetIdentifier(bundle);
                if (bundleID != NULL) {
                    CFStringGetCString(bundleID, tmpBuffer, STRBUF_LEN, CFStringGetSystemEncoding());
                    printf("\tbundle ID: %s\n", tmpBuffer);
                }
                CFRelease(bundle);
            }
        }
        
        // kind string
        err = LSCopyKindStringForURL(url, &kind);
        if (err != noErr) osstatusexit(err, "unable to get kind of '%s'", strBuffer);
        CFStringGetCString(kind, tmpBuffer, STRBUF_LEN, CFStringGetSystemEncoding());
        printf("\tkind: %s\n", tmpBuffer);
        printMoreInfoFromURL(url);
    }
    CFRelease(scheme);
    CFRelease(pathOrURL);
}


void launchURL(CFURLRef url, ICInstance icInst) {
    CFStringRef urlStr = CFURLGetString(url);
    static char strBuffer[STRBUF_LEN];
    long strStart, strEnd;
    OSStatus err;

    strBuffer[0] = '\0';
    CFStringGetCString(urlStr, strBuffer, STRBUF_LEN, CFStringGetSystemEncoding()); // XXX buffer size issues?
    strStart = 0;
    strEnd = strlen(strBuffer);
    err = ICLaunchURL(icInst, "\p", strBuffer, strEnd, &strStart, &strEnd);
    if (err != noErr) {
        fprintf(stderr, "%s: unable to launch URL <%s>: %s\n", APP_NAME, strBuffer, osstatusstr(err));
    }
    
    CFRelease(urlStr);
}

int main (int argc, char * const argv[]) {
    OSStatus err;
    
    APP_NAME = argv[0];
    getargs(argc, argv);

    if (OPTS.action == ACTION_FIND || OPTS.action == ACTION_OPEN) {
        if (LSPEC.appURL != NULL) goto findOK; // already have an application URL
	err = LSFindApplicationForInfo(OPTS.creator, OPTS.bundleID, OPTS.name, NULL, &LSPEC.appURL);
        
	if (err != noErr) {
	    if (OPTS.name != NULL && !CFStringHasSuffix(OPTS.name, CFSTR(".app"))) {
		OPTS.name = CFStringCreateMutableCopy(NULL, CFStringGetLength(OPTS.name) + 4, OPTS.name);
		CFStringAppend((CFMutableStringRef)OPTS.name, CFSTR(".app"));
		err = LSFindApplicationForInfo(OPTS.creator, OPTS.bundleID, OPTS.name, NULL, &LSPEC.appURL);
		if (err == noErr) goto findOK;
	    }
	    osstatusexit(err, "can't locate application", argv[1]);
        findOK: ;
	}
    }
    
    switch (OPTS.action) {
    case ACTION_FIND:
	printPathFromURL(LSPEC.appURL, NULL);
	break;
    case ACTION_OPEN:
	err = LSOpenFromURLSpec(&LSPEC, NULL);
	if (err != noErr) osstatusexit(err, "can't open application", argv[1]);
	break;
    case ACTION_FIND_ITEMS:
        CFArrayApplyFunction(LSPEC.itemURLs, CFRangeMake(0, CFArrayGetCount(LSPEC.itemURLs)),
			     (CFArrayApplierFunction) printPathFromURL, NULL);
	break;
    case ACTION_OPEN_ITEMS:
	err = LSOpenFromURLSpec(&LSPEC, NULL);
	if (err != noErr) osstatusexit(err, "can't open items", argv[1]);
	break;
    case ACTION_INFO_ITEMS:
        CFArrayApplyFunction(LSPEC.itemURLs, CFRangeMake(0, CFArrayGetCount(LSPEC.itemURLs)),
			     (CFArrayApplierFunction) printInfoFromURL, NULL);
	break;
    case ACTION_LAUNCH_URLS:
    {
        ICInstance icInst;
        err = ICStart(&icInst, '????');
        if (err != noErr) osstatusexit(err, "can't initialize Internet Config", argv[1]);
        CFArrayApplyFunction(LSPEC.itemURLs, CFRangeMake(0, CFArrayGetCount(LSPEC.itemURLs)),
                             (CFArrayApplierFunction) launchURL, icInst);
        ICStop(icInst);
        break;
    }
    }

    if (TEMPFILE != NULL) {
        // the application may take a while to finish opening the temporary file
        daemon(0, 0);
        sleep(60);
        unlink(TEMPFILE);
    }

    return 0;
}