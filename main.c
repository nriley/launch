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

#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <Carbon/Carbon.h>

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
    Boolean appSpecified;
    Boolean forceURLs;
    enum { ACTION_FIND, ACTION_FIND_ITEMS,
	   ACTION_OPEN, ACTION_OPEN_ITEMS,
	   ACTION_INFO_ITEMS, ACTION_LAUNCH_URLS } action;
} OPTS =
{
    kLSUnknownCreator, NULL, NULL, false, false,
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
    // Misc. errors
    { nsvErr, "the volume cannot be found (buggy filesystem?)" },
    { procNotFound, "unable to connect to system service.\nAre you logged in?" },
    { kCGErrorIllegalArgument, "window server error.\nAre you logged in?" },
    { fnfErr, "file not found" },
    { eofErr, "data not found" },
    { 0, NULL }
};

void __attribute__((__noreturn__)) usage() {
    fprintf(stderr, "usage: %s [-nplswbmhLU] [-c creator] [-i bundleID] [-u URL] [-a name|path] [-o argument] [item ...] [-]\n"
                    "   or: %s [-npflswbmhLU] "
                    "[-o argument] "
                    "item ...\n", APP_NAME, APP_NAME);
    fprintf(stderr,
        "  -n            print matching paths/URLs instead of opening them\n"
        "  -p            ask application(s) to print document(s)\n"
	"  -f            display information about item(s)\n"
        "  -l            launch URLs (interpret schemeless as http/mailto, not file)\n"
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
        "  -i bundle ID  match application by bundle identifier (com.apple.ScriptEditor2)\n"
        "  -u URL        open application at file:// URL (NOT RECOMMENDED for scripts)\n"
        "  -a name|path  match application by name/path (NOT RECOMMENDED for scripts)\n"
        "  -o argument   pass argument to application (may be specified more than once)\n"
        "A document may be a file, folder, or disk - whatever the application can open.\n"
        "An item may be a file, folder, disk, or URL.\n\n");
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
    if (str != NULL && str != FAILED_STR) {
        free(str);
        str = NULL;
    }
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

char *mallocedUTF8StrFromCFString(CFStringRef string) {
    CFIndex size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(string), kCFStringEncodingUTF8);
    char *str = malloc(size);
    if (str == NULL)
        return NULL;
    if (!CFStringGetCString(string, str, size, kCFStringEncodingUTF8)) {
        free(str);
        return NULL;
    }
    return str;
}

char *cferrorstr(CFErrorRef error) {
    CFStringRef string = CFErrorCopyFailureReason(error);
    if (string == NULL)
        string = CFErrorCopyDescription(error); // will never return NULL
    static char *str = NULL;
    if (str != NULL && str != FAILED_STR) {
        free(str);
        str = NULL;
    }
    str = mallocedUTF8StrFromCFString(string) || FAILED_STR;
    CFRelease(string);
    CFRelease(error);
    return str;
}

void  __attribute__((__noreturn__)) osstatusexit(OSStatus err, const char *fmt, ...) {
    va_list ap;
    const char *errDesc = osstatusstr(err);
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", APP_NAME);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", errDesc);
    exit(1);
}

void __attribute__((__noreturn__)) errexit(const char *fmt, ...) {
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
	    OPTS.appSpecified = true;
            break;
        case 'i':
            OPTS.bundleID = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
	    OPTS.appSpecified = true;
            break;
        case 'a':
            { CFURLRef appURL = CFURLCreateFromFileSystemRepresentation(NULL, (UInt8 *)optarg, strlen(optarg), false);
              if (appURL != NULL) {
                  OPTS.appSpecified = CFURLGetFSRef(appURL, &APPLICATION);
                  CFRelease(appURL);
              }
            }
            if (OPTS.appSpecified) {
                LPARAMS.application = &APPLICATION;
            } else {
                OPTS.name = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
                OPTS.appSpecified = true;
            }
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
	    OPTS.appSpecified = true;
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
	    errexit("without items, must specify an application by -u, or one or more of -c, -i, -a");
        if (!OPTS.appSpecified) {
            if (OPTS.action == ACTION_FIND)
                OPTS.action = ACTION_FIND_ITEMS;
            if (OPTS.action == ACTION_OPEN)
                OPTS.action = ACTION_OPEN_ITEMS;
        }
    } else {
	if (LPARAMS.application != NULL)
	    errexit("application URL (argument of -u) incompatible with matching by -c, -i, -a");
    }

    if (OPTS.action == ACTION_INFO_ITEMS && OPTS.appSpecified)
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
        // failure is handled by just returning the empty string
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

void printAbsoluteTime(const char *label, CFAbsoluteTime absoluteTime, const char *postStr) {
    static CFDateFormatterRef formatter = NULL;
    static char strBuffer[STRBUF_LEN];
    if (formatter == NULL) {
	formatter = CFDateFormatterCreate(NULL, CFLocaleCopyCurrent(), kCFDateFormatterShortStyle, kCFDateFormatterMediumStyle);
    }

    CFStringRef dateTimeString = CFDateFormatterCreateStringWithAbsoluteTime(NULL, formatter, absoluteTime);
    if (dateTimeString == NULL || !CFStringGetCString(dateTimeString, strBuffer, STRBUF_LEN, kCFStringEncodingUTF8))
        strcpy(strBuffer, "[can't format]");

    if (dateTimeString != NULL)
        CFRelease(dateTimeString);
    printf("\t%s: %s%s\n", label, strBuffer, postStr);
}

void printDateTime(const char *label, UTCDateTime *utcTime, const char *postStr, Boolean printIfEmpty) {
    CFAbsoluteTime absoluteTime;
    OSStatus err;

    err = UCConvertUTCDateTimeToCFAbsoluteTime(utcTime, &absoluteTime);
    if (err == kUTCUnderflowErr) {
        if (printIfEmpty) printf("\t%s: (not set)\n", label);
        return;
    }
    if (err != noErr) osstatusexit(err, "unable to convert UTC %s time", label);

    printAbsoluteTime(label, absoluteTime, postStr);
}

#define DFORMAT(SIZE) ((float)(SIZE) / 1024.)

void printPhysicalSize(UInt64 physicalSize) {
    if (physicalSize == 0) {
        printf("zero bytes");
        return;
    }
    UInt32 bigSize = physicalSize >> 32, littleSize = physicalSize;
    if (bigSize == 0) {
        if (littleSize < 1024)
            printf("%lu bytes", littleSize);
        else {
            UInt32 adjSize = littleSize >> 10;
            if (adjSize < 1024) printf("%.1f KB", DFORMAT(littleSize));
            else {
                adjSize >>= 10; littleSize >>= 10;
                if (adjSize < 1024) printf("%.2f MB", DFORMAT(littleSize));
                else {
                    /* adjSize >>= 10; */ littleSize >>= 10;
                    printf("%.2f GB", DFORMAT(littleSize));
                }
            }
        }
    } else {
        if (bigSize < 1024) { // < 4 TB
            printf("%.2f GB", (float)(bigSize * 4 + littleSize / 1073741824.));
        } else {
            bigSize >>= 8;
            printf("%lu TB", bigSize);
        }
    }
}

void printSize(SInt64 size) {
    if (size < 0)
        printf("%lld bytes", size);
    else
        printPhysicalSize((UInt64)size);
}

Boolean booleanProp(CFDictionaryRef props, CFStringRef key, Boolean *boolean) {
    CFTypeRef value = CFDictionaryGetValue(props, key);
    if (value == NULL || CFGetTypeID(value) != CFBooleanGetTypeID())
        return false;

    *boolean = CFBooleanGetValue((CFBooleanRef)value);
    return true;
}

Boolean printBooleanProp(CFDictionaryRef props, CFStringRef key, char *yesStr, char *noStr, char *unknownStr, char *preStr, char *postStr) {
    char *str;
    Boolean boolean;
    if (booleanProp(props, key, &boolean)) {
        str = boolean ? yesStr : noStr;
    } else {
        str = unknownStr;
    }

    if (str)
        printf("%s %s%s", preStr ? preStr : "", str, postStr ? postStr : "");

    return str != NULL;
}

static Boolean haveBooleanPropItem;
Boolean printBooleanPropItem(CFDictionaryRef props, CFStringRef key, char *yesStr, char *noStr) {
    char *preStr = NULL;
    if (haveBooleanPropItem)
        preStr = ",";

    Boolean printed = printBooleanProp(props, key, yesStr, noStr, NULL, preStr, NULL);
    if (!haveBooleanPropItem)
        haveBooleanPropItem = printed;

    return printed;
}

Boolean printPropItemIfYes(CFDictionaryRef props, CFStringRef key, char *yesStr) {
    return printBooleanPropItem(props, key, yesStr, NULL);
}

void beginBooleanPropItemList(char *label) {
    printf("\t%s:", label);
    haveBooleanPropItem = false;
}

void endBooleanPropItemList(char *noItemsStr) {
    if (!haveBooleanPropItem)
        printf(" %s", noItemsStr);
    printf("\n");
    haveBooleanPropItem = false;
}

Boolean strProp(CFDictionaryRef props, CFStringRef key, char **strPtr) {
    static char *str = NULL;
    if (str != NULL) {
        free(str);
        str = NULL;
    }

    CFTypeRef value = CFDictionaryGetValue(props, key);
    if (value == NULL) {
        *strPtr = NULL;
        return false;
    }

    if (CFGetTypeID(value) != CFStringGetTypeID()) {
        *strPtr = "[unexpected value]";
        return false;
    }

    str = mallocedUTF8StrFromCFString((CFStringRef)value);
    if (str == NULL) {
        *strPtr = "[can't retrieve]";
        return false;
    }

    *strPtr = str;
    return true;
}

Boolean printStringProp(CFDictionaryRef props, CFStringRef key, char *label, char *preStr, char *postStr) {
    char *str;
    Boolean retrieved = strProp(props, key, &str);
    if (retrieved)
        printf("\t%s: %s%s%s\n", label, preStr ? preStr : "", str, postStr ? postStr : "");
    else if (str != NULL)
        printf("\t%s: %s\n", label, str);

    return retrieved;
}

Boolean urlProp(CFDictionaryRef props, CFStringRef key, char **strPtr) {
    static char *str = NULL;
    if (str != NULL) {
        free(str);
        str = NULL;
    }

    CFTypeRef value = CFDictionaryGetValue(props, key);
    if (value == NULL) {
        *strPtr = NULL;
        return false;
    }

    if (CFGetTypeID(value) != CFURLGetTypeID()) {
        *strPtr = "[unexpected value]";
        return false;
    }

    CFStringRef string = CFURLGetString((CFURLRef)value);
    if (string == NULL) {
        *strPtr = "[can't extract URL]";
        return false;
    }
    str = mallocedUTF8StrFromCFString(string);
    if (str == NULL) {
        *strPtr = "[can't retrieve URL]";
        return false;
    }

    *strPtr = str;
    return true;
}

Boolean printURLProp(CFDictionaryRef props, CFStringRef key, char *label) {
    char *str;
    Boolean retrieved = urlProp(props, key, &str);
    if (retrieved)
        printf("\t%s: <%s>\n", label, str);
    else if (str != NULL)
        printf("\t%s: %s\n", label, str);

    return retrieved;
}

Boolean sInt64Prop(CFDictionaryRef props, CFStringRef key, SInt64 *sInt64Ptr) {
    CFTypeRef value = CFDictionaryGetValue(props, key);
    if (value == NULL || CFGetTypeID(value) != CFNumberGetTypeID())
        return false;
    CFNumberRef number = (CFNumberRef)value;
    if (CFNumberIsFloatType(number))
        return false;
    return CFNumberGetValue(number, kCFNumberSInt64Type, sInt64Ptr);
}

Boolean printSizeProp(CFDictionaryRef props, CFStringRef key, char *label) {
    SInt64 sInt64;
    Boolean retrieved = sInt64Prop(props, key, &sInt64);
    if (retrieved) {
        printf("\t%s: ", label);
        printSize(sInt64);
        printf("\n");
    }

    return retrieved;
}

Boolean printSizesProp(CFDictionaryRef props, CFStringRef logicalSizeKey, CFStringRef physicalSizeKey, char *label) {
    SInt64 logicalSize = 0, physicalSize = 0;
    Boolean logicalSizeRetrieved = sInt64Prop(props, logicalSizeKey, &logicalSize);
    Boolean physicalSizeRetrieved = sInt64Prop(props, physicalSizeKey, &physicalSize);
    if (!logicalSizeRetrieved && !physicalSizeRetrieved)
        return false;

    printf("\t%s: ", label);
    if (logicalSizeRetrieved && physicalSizeRetrieved) {
        if (physicalSize == 0) {
            printf("zero bytes on disk (zero bytes used)\n");
        } else {
            printPhysicalSize(physicalSize);
            printf(" on disk (%llu bytes used)\n", logicalSize);
        }
    } else {
        printPhysicalSize(logicalSize || physicalSize);
    }
    return true;
}

Boolean dateProp(CFDictionaryRef props, CFStringRef key, CFAbsoluteTime *absoluteTimePtr) {
    CFTypeRef value = CFDictionaryGetValue(props, key);
    if (value == NULL || CFGetTypeID(value) != CFDateGetTypeID())
        return false;
    *absoluteTimePtr = CFDateGetAbsoluteTime((CFDateRef)value);
    return true;
}

Boolean printDateProp(CFDictionaryRef props, CFStringRef key, char *label) {
    CFAbsoluteTime absoluteTime;
    Boolean retrieved = dateProp(props, key, &absoluteTime);
    if (retrieved) {
        printAbsoluteTime(label, absoluteTime, "");
    }

    return retrieved;
}

void printMoreInfoForVolume(CFURLRef url) {
    const CFStringRef VOLUME_KEYS[] = {
        kCFURLVolumeLocalizedFormatDescriptionKey,
        kCFURLVolumeSupportsVolumeSizesKey, // if next 2 are valid
        kCFURLVolumeTotalCapacityKey, kCFURLVolumeAvailableCapacityKey,
        kCFURLVolumeResourceCountKey,
        kCFURLVolumeSupportsPersistentIDsKey,
        kCFURLVolumeSupportsSymbolicLinksKey, kCFURLVolumeSupportsHardLinksKey,
        kCFURLVolumeSupportsJournalingKey, kCFURLVolumeIsJournalingKey,
        kCFURLVolumeSupportsSparseFilesKey, kCFURLVolumeSupportsZeroRunsKey,
        kCFURLVolumeSupportsCaseSensitiveNamesKey,
        kCFURLVolumeSupportsCasePreservedNamesKey,
        // kCFURLVolumeSupportsRootDirectoryDatesKey,
        kCFURLVolumeSupportsRenamingKey, kCFURLVolumeSupportsAdvisoryFileLockingKey,
        kCFURLVolumeSupportsExtendedSecurityKey, kCFURLVolumeIsBrowsableKey,
        kCFURLVolumeMaximumFileSizeKey,
        kCFURLVolumeIsEjectableKey, kCFURLVolumeIsRemovableKey,
        kCFURLVolumeIsInternalKey, kCFURLVolumeIsAutomountedKey,
        kCFURLVolumeIsLocalKey, kCFURLVolumeIsReadOnlyKey,
        kCFURLVolumeURLForRemountingKey, kCFURLVolumeUUIDStringKey
    };
    CFArrayRef keys = CFArrayCreate(NULL, (const void **)&VOLUME_KEYS, sizeof(VOLUME_KEYS)/sizeof(CFStringRef *), NULL);
    if (keys == NULL) {
        printf("\t[can't get volume information]\n");
        return;
    }
    CFErrorRef error;
    CFDictionaryRef props = CFURLCopyResourcePropertiesForKeys(url, keys, &error);
    CFRelease(keys);
    if (props == NULL) {
        printf("\t[can't get volume information: %s]\n", cferrorstr(error));
        return;
    }

    printStringProp(props, kCFURLVolumeLocalizedFormatDescriptionKey, "filesystem", NULL, NULL);
    SInt64 resourceCount;
    if (sInt64Prop(props, kCFURLVolumeResourceCountKey, &resourceCount))
        printf("\tfiles and folders: %lld\n", resourceCount);

    Boolean supportsVolumeSizes;
    if (booleanProp(props, kCFURLVolumeSupportsVolumeSizesKey, &supportsVolumeSizes) && supportsVolumeSizes) {
        printSizeProp(props, kCFURLVolumeTotalCapacityKey, "capacity");
        printSizeProp(props, kCFURLVolumeAvailableCapacityKey, "available");
    }
    printSizeProp(props, kCFURLVolumeMaximumFileSizeKey, "maximum file size");

    beginBooleanPropItemList("is");
    printPropItemIfYes(props, kCFURLVolumeIsEjectableKey, "ejectable");
    printBooleanPropItem(props, kCFURLVolumeIsRemovableKey, "removable", "fixed");
    printPropItemIfYes(props, kCFURLVolumeIsInternalKey, "internal");
    printPropItemIfYes(props, kCFURLVolumeIsAutomountedKey, "automounted");
    printBooleanPropItem(props, kCFURLVolumeIsLocalKey, "local", "remote");
    printBooleanPropItem(props, kCFURLVolumeIsReadOnlyKey, "read-only", "read-write");
    printPropItemIfYes(props, kCFURLVolumeSupportsRenamingKey, "renamable");
    printBooleanPropItem(props, kCFURLVolumeIsBrowsableKey, "visible in UI", "not visible in UI");
    endBooleanPropItemList("none");

    beginBooleanPropItemList("supports");
    printPropItemIfYes(props, kCFURLVolumeSupportsSymbolicLinksKey, "symlinks");
    printPropItemIfYes(props, kCFURLVolumeSupportsHardLinksKey, "hard links");
    printPropItemIfYes(props, kCFURLVolumeSupportsSparseFilesKey, "sparse files");
    printPropItemIfYes(props, kCFURLVolumeSupportsZeroRunsKey, "zero runs");
    printPropItemIfYes(props, kCFURLVolumeSupportsAdvisoryFileLockingKey, "advisory locking");
    printPropItemIfYes(props, kCFURLVolumeSupportsExtendedSecurityKey, "ACLs");
    printPropItemIfYes(props, kCFURLVolumeSupportsPersistentIDsKey, "persistent IDs");
    endBooleanPropItemList("none");

    beginBooleanPropItemList("names");
    printBooleanPropItem(props, kCFURLVolumeSupportsCaseSensitiveNamesKey, "case-sensitive", "case-insensitive");
    // AppleShare reports false here, which if displayed could be confusing
    printPropItemIfYes(props, kCFURLVolumeSupportsCasePreservedNamesKey, "case-preserving");
    endBooleanPropItemList("unknown");

    printf("\tjournaling:");
    Boolean journalingSupportKnown = printBooleanProp(props, kCFURLVolumeSupportsJournalingKey, "supported", "not supported", NULL, NULL, ",");
    printBooleanProp(props, kCFURLVolumeIsJournalingKey, "active", "inactive", journalingSupportKnown ? NULL : "unknown", NULL, NULL);
    printf("\n");

    printStringProp(props, kCFURLVolumeUUIDStringKey, "UUID", NULL, NULL);
    printURLProp(props, kCFURLVolumeURLForRemountingKey, "URL");
    CFRelease(props);
}

Boolean valence(CFURLRef url, SInt64 *count) {
    CFStringRef path = CFURLCopyFileSystemPath(url, kCFURLPOSIXPathStyle);
    if (path == NULL)
        return false;

    static char strBuffer[STRBUF_LEN];
    if (!CFStringGetFileSystemRepresentation(path, strBuffer, STRBUF_LEN))
        return false;

    DIR *dir = opendir(strBuffer);
    if (dir == NULL)
        return false;

    struct dirent *entry;
    *count = 0;
    while ( (entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        (*count)++;
    }
    closedir(dir);

    return true;
}

void printValence(CFURLRef url) {
    SInt64 count;
    Boolean success = valence(url, &count);
    if (!success)
        return;
    printf("\tcontents: ");
    switch (count) {
	case 0: printf("zero items\n"); break;
	case 1: printf("1 item\n"); break;
	default: printf("%lld items\n", count);
    }
}

const char *utf8StrFromCFString(CFStringRef string) {
    static char tmpBuffer[STRBUF_LEN];
    if (CFStringGetCString(string, tmpBuffer, STRBUF_LEN, kCFStringEncodingUTF8))
        return tmpBuffer;

    static char *str = NULL;
    if (str != NULL) {
        free(str);
        str = NULL;
    }
    str = mallocedUTF8StrFromCFString(string);
    return str;
}

const char *utf8StrFromOSType(OSType osType) {
    osType = ntohl(osType);
    CFStringRef typeStr = CFStringCreateWithBytes(NULL, (UInt8 *)&osType, 4, CFStringGetSystemEncoding(), false);
    if (typeStr == NULL) {
	// punt to displaying verbatim
	static char tmpBuffer[5];
	tmpBuffer[4] = '\0';
	strncpy(tmpBuffer, (const char *)&osType, 4);
	return tmpBuffer;
    }
    const char *buffer = utf8StrFromCFString(typeStr);
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
        if (printOnFailure) printf("[can't get executable]\n");
        return;
    }

    int fd = open((const char *)path, O_RDONLY, 0777);
    if (fd <= 0) {
        if (printOnFailure) printf("[can't read]\n");
        return;
    }

    uint8_t bytes[MAX_HEADER_BYTES];
    ssize_t length = read(fd, bytes, MAX_HEADER_BYTES);
    close(fd);

    if (length < sizeof(struct mach_header_64)) {
        if (printOnFailure) printf("[can't read Mach-O header]\n");
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

    const CFStringRef KEYS[] = {
        kCFURLIsSystemImmutableKey, kCFURLIsUserImmutableKey, //
        kCFURLHasHiddenExtensionKey, //
        kCFURLCreationDateKey, kCFURLContentAccessDateKey, //
        kCFURLContentModificationDateKey, //
        kCFURLLinkCountKey, kCFURLLabelNumberKey, kCFURLLocalizedLabelKey,
        kCFURLIsExcludedFromBackupKey, // triggers <http://www.openradar.me/15772932>
        kCFURLFileResourceTypeKey, //
        kCFURLFileSizeKey, kCFURLFileAllocatedSizeKey,
        kCFURLTotalFileSizeKey, kCFURLTotalFileAllocatedSizeKey
    };
    CFArrayRef keys = CFArrayCreate(NULL, (const void **)&KEYS, sizeof(KEYS)/sizeof(CFStringRef *), NULL);
    if (keys == NULL) {
        printf("[can't get more information]\n");
        return;
    }
    CFErrorRef error = NULL;

    // work around <http://www.openradar.me/15772932>
    CFStringRef urlString = CFURLGetString(url);
    CFRetain(urlString);
    CFIndex retainCountBefore = CFGetRetainCount(urlString);
    CFDictionaryRef props = CFURLCopyResourcePropertiesForKeys(url, keys, &error);
    CFRelease(keys);
    if (retainCountBefore == CFGetRetainCount(urlString))
        CFRelease(urlString); // make a noop after the bug is fixed
    if (props == NULL) {
        printf("[can't get more information: %s]\n", cferrorstr(error));
        return;
    }

    // modifiers
    if (info.flags & kLSItemInfoIsInvisible) printf("invisible ");
    if (info.flags & kLSItemInfoAppIsScriptable) printf("scriptable ");
    if (info.flags & kLSItemInfoIsNativeApp) printf("OS X ");
    if (info.flags & kLSItemInfoIsClassicApp) printf("Classic ");

    // kind
    CFTypeRef resourceType = CFDictionaryGetValue(props, kCFURLFileResourceTypeKey);
    if (info.flags & kLSItemInfoIsVolume) printf("volume");
    else if (info.flags & kLSItemInfoIsApplication) printf("application ");
    else if (info.flags & kLSItemInfoIsPackage) printf("non-application ");
    else if (info.flags & kLSItemInfoIsContainer) printf("folder");
    else if (info.flags & kLSItemInfoIsSymlink) printf("symbolic link");
    else if (info.flags & kLSItemInfoIsAliasFile) printf("alias");
    else if (resourceType == kCFURLFileResourceTypeNamedPipe) printf("named pipe");
    else if (resourceType == kCFURLFileResourceTypeCharacterSpecial) printf("character device");
    else if (resourceType == kCFURLFileResourceTypeBlockSpecial) printf("block device");
    else if (resourceType == kCFURLFileResourceTypeSocket) printf("socket");
    else if (info.flags & kLSItemInfoIsPlainFile) printf("document");
    else printf("unknown");

    if (info.flags & kLSItemInfoIsPackage) printf("package ");

    if (info.flags & kLSItemInfoAppPrefersNative) printf("[Carbon, prefers native OS X]");
    else if (info.flags & kLSItemInfoAppPrefersClassic) printf("[Carbon, prefers Classic]");

    printf("\n");
    if (!(info.flags & kLSItemInfoIsContainer) || info.flags & kLSItemInfoIsPackage) {
	printf("\ttype: '%s'", utf8StrFromOSType(info.filetype));
	printf("\tcreator: '%s'\n", utf8StrFromOSType(info.creator));
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
    } else if (info.flags & kLSItemInfoIsPackage && !haveFSRef) {
	printf("\t[can't access package contents]\n");
    } else if (haveFSRef) {
	CFPropertyListRef infoPlist = CFBundleCopyInfoDictionaryForURL(url);
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
	printExecutableArchitectures(url, false);
    }

    if (bundleID != NULL) {
	printf("\tbundle ID: %s\n", utf8StrFromCFString(bundleID));
	CFRelease(bundleID);
    }
    if (version != NULL) {
	printf("\tversion: %s", utf8StrFromCFString(version));
	if (intVersion != 0) printf(" [0x%lx = %lu]", intVersion, intVersion);
	putchar('\n');
	CFRelease(version);
    }

    // kind string
    err = LSCopyKindStringForURL(url, &kind);
    if (err != fnfErr) { // returned on device nodes
        if (err != noErr) osstatusexit(err, "unable to get kind of '%s'", strBuffer);
        printf("\tkind: %s\n", utf8StrFromCFString(kind));
        CFRelease(kind);
    }

    beginBooleanPropItemList("attributes");
    printPropItemIfYes(props, kCFURLIsSystemImmutableKey, "system immutable");
    printPropItemIfYes(props, kCFURLIsUserImmutableKey, "user immutable (locked)");
    printPropItemIfYes(props, kCFURLHasHiddenExtensionKey, "extension hidden");
    printPropItemIfYes(props, kCFURLIsExcludedFromBackupKey, "excluded from backup");
    endBooleanPropItemList("none");

    SInt64 labelNumber;
    if (sInt64Prop(props, kCFURLLabelNumberKey, &labelNumber) && labelNumber > 0) {
        printf("\tlabel: ");
        char *labelName;
        if (strProp(props, kCFURLLocalizedLabelKey, &labelName))
            printf("%s (%lld)\n", labelName, labelNumber);
        else
            printf("%lld\n", labelNumber);
    }

    if (haveFSRef) {
	// content type identifier (UTI)
	err = LSCopyItemAttribute(&fsr, kLSRolesAll, kLSItemContentType, (CFTypeRef *)&kind);
	if (err == noErr) {
	    printf("\tcontent type ID: %s\n", utf8StrFromCFString(kind));
	    CFRelease(kind);
	}
    }

    SInt64 hardLinkCount;
    if (sInt64Prop(props, kCFURLLinkCountKey, &hardLinkCount) && hardLinkCount > 1)
        printf("\thard link count: %lld\n", hardLinkCount);

    if (resourceType == kCFURLFileResourceTypeDirectory) {
        printValence(url);
    } else {
        printSizesProp(props, kCFURLFileSizeKey, kCFURLFileAllocatedSizeKey, "data fork size");
        printSizesProp(props, kCFURLTotalFileSizeKey, kCFURLTotalFileAllocatedSizeKey, "total file size");
    }

    // dates
    printDateProp(props, kCFURLCreationDateKey, "created");
    printDateProp(props, kCFURLContentModificationDateKey, "modified");
    printDateProp(props, kCFURLContentAccessDateKey, "accessed");

    if (info.flags & kLSItemInfoIsVolume) {
        printMoreInfoForVolume(url);
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

    CFRelease(props);
}

OSStatus openItems(void) {
    if (ITEMS == NULL)
        ITEMS = CFArrayCreate(NULL, NULL, 0, NULL);
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

    if (OPTS.appSpecified && LPARAMS.application == NULL) {
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
    case ACTION_LAUNCH_URLS:
        err = openItems();
        if (err != noErr) osstatusexit(err, "can't launch URLs");
        break;
    case ACTION_INFO_ITEMS:
        CFArrayApplyFunction(ITEMS, CFRangeMake(0, CFArrayGetCount(ITEMS)),
			     (CFArrayApplierFunction) printInfoFromURL, NULL);
        break;
    }

    if (TEMPFILE != NULL) {
        // the application may take a while to finish opening the temporary file
        background();
        sleep(60);
        unlink(TEMPFILE);
    }

    return 0;
}
