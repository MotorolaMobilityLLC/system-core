// Copyright 2006-2015 The Android Open Source Project

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <cutils/sched_policy.h>
#include <cutils/sockets.h>
#include <log/event_tag_map.h>
#include <log/log.h>
#include <log/log_read.h>
#include <log/logd.h>
#include <log/logger.h>
#include <log/logprint.h>
#include <utils/threads.h>

#include <pcrecpp.h>

#define DEFAULT_MAX_ROTATED_LOGS 4

static AndroidLogFormat * g_logformat;

/* logd prefixes records with a length field */
#define RECORD_LENGTH_FIELD_SIZE_BYTES sizeof(uint32_t)

struct log_device_t {
    const char* device;
    bool binary;
    struct logger *logger;
    struct logger_list *logger_list;
    bool printed;

    log_device_t* next;

    log_device_t(const char* d, bool b) {
        device = d;
        binary = b;
        next = NULL;
        printed = false;
        logger = NULL;
        logger_list = NULL;
    }
};

namespace android {

/* Global Variables */

static const char * g_outputFileName;
// 0 means "no log rotation"
static size_t g_logRotateSizeKBytes;
// 0 means "unbounded"
static size_t g_maxRotatedLogs = DEFAULT_MAX_ROTATED_LOGS;
static int g_outFD = -1;
static size_t g_outByteCount;
static int g_printBinary;
static int g_devCount;                              // >1 means multiple
static pcrecpp::RE* g_regex;
// 0 means "infinite"
static size_t g_maxCount;
static size_t g_printCount;

// if showHelp is set, newline required in fmt statement to transition to usage
__noreturn static void logcat_panic(bool showHelp, const char *fmt, ...) __printflike(2,3);

static int openLogFile (const char *pathname)
{
    return open(pathname, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
}

static void rotateLogs()
{
    int err;

    // Can't rotate logs if we're not outputting to a file
    if (g_outputFileName == NULL) {
        return;
    }

    close(g_outFD);

    // Compute the maximum number of digits needed to count up to g_maxRotatedLogs in decimal.
    // eg: g_maxRotatedLogs == 30 -> log10(30) == 1.477 -> maxRotationCountDigits == 2
    int maxRotationCountDigits =
            (g_maxRotatedLogs > 0) ? (int) (floor(log10(g_maxRotatedLogs) + 1)) : 0;

    for (int i = g_maxRotatedLogs ; i > 0 ; i--) {
        char *file0, *file1;

        asprintf(&file1, "%s.%.*d", g_outputFileName, maxRotationCountDigits, i);

        if (i - 1 == 0) {
            asprintf(&file0, "%s", g_outputFileName);
        } else {
            asprintf(&file0, "%s.%.*d", g_outputFileName, maxRotationCountDigits, i - 1);
        }

        if (!file0 || !file1) {
            perror("while rotating log files");
            break;
        }

        err = rename(file0, file1);

        if (err < 0 && errno != ENOENT) {
            perror("while rotating log files");
        }

        free(file1);
        free(file0);
    }

    g_outFD = openLogFile(g_outputFileName);

    if (g_outFD < 0) {
        logcat_panic(false, "couldn't open output file");
    }

    g_outByteCount = 0;

}

void printBinary(struct log_msg *buf)
{
    size_t size = buf->len();

    TEMP_FAILURE_RETRY(write(g_outFD, buf, size));
}

static bool regexOk(const AndroidLogEntry& entry)
{
    if (!g_regex) {
        return true;
    }

    std::string messageString(entry.message, entry.messageLen);

    return g_regex->PartialMatch(messageString);
}

static void processBuffer(log_device_t* dev, struct log_msg *buf)
{
    int bytesWritten = 0;
    int err;
    AndroidLogEntry entry;
    char binaryMsgBuf[1024];

    if (dev->binary) {
        static bool hasOpenedEventTagMap = false;
        static EventTagMap *eventTagMap = NULL;

        if (!eventTagMap && !hasOpenedEventTagMap) {
            eventTagMap = android_openEventTagMap(EVENT_TAG_MAP_FILE);
            hasOpenedEventTagMap = true;
        }
        err = android_log_processBinaryLogBuffer(&buf->entry_v1, &entry,
                                                 eventTagMap,
                                                 binaryMsgBuf,
                                                 sizeof(binaryMsgBuf));
        //printf(">>> pri=%d len=%d msg='%s'\n",
        //    entry.priority, entry.messageLen, entry.message);
    } else {
        err = android_log_processLogBuffer(&buf->entry_v1, &entry);
    }
    if (err < 0) {
        goto error;
    }

    if (android_log_shouldPrintLine(g_logformat, entry.tag, entry.priority) &&
            regexOk(entry)) {
        bytesWritten = android_log_printLogLine(g_logformat, g_outFD, &entry);

        g_printCount++;

        if (bytesWritten < 0) {
            logcat_panic(false, "output error");
        }
    }

    g_outByteCount += bytesWritten;

    if (g_logRotateSizeKBytes > 0
        && (g_outByteCount / 1024) >= g_logRotateSizeKBytes
    ) {
        rotateLogs();
    }

error:
    //fprintf (stderr, "Error processing record\n");
    return;
}

static void maybePrintStart(log_device_t* dev, bool printDividers) {
    if (!dev->printed || printDividers) {
        if (g_devCount > 1 && !g_printBinary) {
            char buf[1024];
            snprintf(buf, sizeof(buf), "--------- %s %s\n",
                     dev->printed ? "switch to" : "beginning of",
                     dev->device);
            if (write(g_outFD, buf, strlen(buf)) < 0) {
                logcat_panic(false, "output error");
            }
        }
        dev->printed = true;
    }
}

static void setupOutput()
{

    if (g_outputFileName == NULL) {
        g_outFD = STDOUT_FILENO;

    } else {
        if (set_sched_policy(0, SP_BACKGROUND) < 0) {
            fprintf(stderr, "failed to set background scheduling policy\n");
        }

        struct sched_param param;
        memset(&param, 0, sizeof(param));
        if (sched_setscheduler((pid_t) 0, SCHED_BATCH, &param) < 0) {
            fprintf(stderr, "failed to set to batch scheduler\n");
        }

        if (setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND) < 0) {
            fprintf(stderr, "failed set to priority\n");
        }

        g_outFD = openLogFile (g_outputFileName);

        if (g_outFD < 0) {
            logcat_panic(false, "couldn't open output file");
        }

        struct stat statbuf;
        if (fstat(g_outFD, &statbuf) == -1) {
            close(g_outFD);
            logcat_panic(false, "couldn't get output file stat\n");
        }

        if ((size_t) statbuf.st_size > SIZE_MAX || statbuf.st_size < 0) {
            close(g_outFD);
            logcat_panic(false, "invalid output file stat\n");
        }

        g_outByteCount = statbuf.st_size;
    }
}

static void show_help(const char *cmd)
{
    fprintf(stderr,"Usage: %s [options] [filterspecs]\n", cmd);

    fprintf(stderr, "options include:\n"
                    "  -s              Set default filter to silent.\n"
                    "                  Like specifying filterspec '*:S'\n"
                    "  -f <filename>   Log to file. Default is stdout\n"
                    "  --file=<filename>\n"
                    "  -r <kbytes>     Rotate log every kbytes. Requires -f\n"
                    "  --rotate-kbytes=<kbytes>\n"
                    "  -n <count>      Sets max number of rotated logs to <count>, default 4\n"
                    "  --rotate-count=<count>\n"
                    "  -v <format>     Sets the log print format, where <format> is:\n"
                    "  --format=<format>\n"
                    "                      brief color epoch long monotonic printable process raw\n"
                    "                      tag thread threadtime time uid usec UTC year zone\n\n"
                    "  -D              print dividers between each log buffer\n"
                    "  --dividers\n"
                    "  -c              clear (flush) the entire log and exit\n"
                    "  --clear\n"
                    "  -d              dump the log and then exit (don't block)\n"
                    "  -e <expr>       only print lines where the log message matches <expr>\n"
                    "  --regex <expr>  where <expr> is a regular expression\n"
                    "  -m <count>      quit after printing <count> lines. This is meant to be\n"
                    "  --max-count=<count> paired with --regex, but will work on its own.\n"
                    "  -t <count>      print only the most recent <count> lines (implies -d)\n"
                    "  -t '<time>'     print most recent lines since specified time (implies -d)\n"
                    "  -T <count>      print only the most recent <count> lines (does not imply -d)\n"
                    "  -T '<time>'     print most recent lines since specified time (not imply -d)\n"
                    "                  count is pure numerical, time is 'MM-DD hh:mm:ss.mmm...'\n"
                    "                  'YYYY-MM-DD hh:mm:ss.mmm...' or 'sssss.mmm...' format\n"
                    "  -g              get the size of the log's ring buffer and exit\n"
                    "  --buffer-size\n"
                    "  -G <size>       set size of log ring buffer, may suffix with K or M.\n"
                    "  --buffer-size=<size>\n"
                    "  -L              dump logs from prior to last reboot\n"
                    "  --last\n"
                    // Leave security (Device Owner only installations) and
                    // kernel (userdebug and eng) buffers undocumented.
                    "  -b <buffer>     Request alternate ring buffer, 'main', 'system', 'radio',\n"
                    "  --buffer=<buffer> 'events', 'crash', 'default' or 'all'. Multiple -b\n"
                    "                  parameters are allowed and results are interleaved. The\n"
                    "                  default is -b main -b system -b crash.\n"
                    "  -B              output the log in binary.\n"
                    "  --binary\n"
                    "  -S              output statistics.\n"
                    "  --statistics\n"
                    "  -p              print prune white and ~black list. Service is specified as\n"
                    "  --prune         UID, UID/PID or /PID. Weighed for quicker pruning if prefix\n"
                    "                  with ~, otherwise weighed for longevity if unadorned. All\n"
                    "                  other pruning activity is oldest first. Special case ~!\n"
                    "                  represents an automatic quicker pruning for the noisiest\n"
                    "                  UID as determined by the current statistics.\n"
                    "  -P '<list> ...' set prune white and ~black list, using same format as\n"
                    "  --prune='<list> ...'  printed above. Must be quoted.\n"
                    "  --pid=<pid>     Only prints logs from the given pid.\n"
                    // Check ANDROID_LOG_WRAP_DEFAULT_TIMEOUT value
                    "  --wrap          Sleep for 2 hours or when buffer about to wrap whichever\n"
                    "                  comes first. Improves efficiency of polling by providing\n"
                    "                  an about-to-wrap wakeup.\n");

    fprintf(stderr,"\nfilterspecs are a series of \n"
                   "  <tag>[:priority]\n\n"
                   "where <tag> is a log component tag (or * for all) and priority is:\n"
                   "  V    Verbose (default for <tag>)\n"
                   "  D    Debug (default for '*')\n"
                   "  I    Info\n"
                   "  W    Warn\n"
                   "  E    Error\n"
                   "  F    Fatal\n"
                   "  S    Silent (suppress all output)\n"
                   "\n'*' by itself means '*:D' and <tag> by itself means <tag>:V.\n"
                   "If no '*' filterspec or -s on command line, all filter defaults to '*:V'.\n"
                   "eg: '*:S <tag>' prints only <tag>, '<tag>:S' suppresses all <tag> log messages.\n"
                   "\nIf not specified on the command line, filterspec is set from ANDROID_LOG_TAGS.\n"
                   "\nIf not specified with -v on command line, format is set from ANDROID_PRINTF_LOG\n"
                   "or defaults to \"threadtime\"\n\n");
}

static int setLogFormat(const char * formatString)
{
    static AndroidLogPrintFormat format;

    format = android_log_formatFromString(formatString);

    if (format == FORMAT_OFF) {
        // FORMAT_OFF means invalid string
        return -1;
    }

    return android_log_setPrintFormat(g_logformat, format);
}

static const char multipliers[][2] = {
    { "" },
    { "K" },
    { "M" },
    { "G" }
};

static unsigned long value_of_size(unsigned long value)
{
    for (unsigned i = 0;
            (i < sizeof(multipliers)/sizeof(multipliers[0])) && (value >= 1024);
            value /= 1024, ++i) ;
    return value;
}

static const char *multiplier_of_size(unsigned long value)
{
    unsigned i;
    for (i = 0;
            (i < sizeof(multipliers)/sizeof(multipliers[0])) && (value >= 1024);
            value /= 1024, ++i) ;
    return multipliers[i];
}

/*String to unsigned int, returns -1 if it fails*/
static bool getSizeTArg(char *ptr, size_t *val, size_t min = 0,
                        size_t max = SIZE_MAX)
{
    if (!ptr) {
        return false;
    }

    char *endp;
    errno = 0;
    size_t ret = (size_t)strtoll(ptr, &endp, 0);

    if (endp[0] || errno) {
        return false;
    }

    if ((ret > max) || (ret < min)) {
        return false;
    }

    *val = ret;
    return true;
}

static void logcat_panic(bool showHelp, const char *fmt, ...)
{
    va_list  args;
    va_start(args, fmt);
    vfprintf(stderr, fmt,  args);
    va_end(args);

    if (showHelp) {
       show_help(getprogname());
    }

    exit(EXIT_FAILURE);
}

static char *parseTime(log_time &t, const char *cp) {

    char *ep = t.strptime(cp, "%m-%d %H:%M:%S.%q");
    if (ep) {
        return ep;
    }
    ep = t.strptime(cp, "%Y-%m-%d %H:%M:%S.%q");
    if (ep) {
        return ep;
    }
    return t.strptime(cp, "%s.%q");
}

// Find last logged line in gestalt of all matching existing output files
static log_time lastLogTime(char *outputFileName) {
    log_time retval(log_time::EPOCH);
    if (!outputFileName) {
        return retval;
    }

    clockid_t clock_type = android_log_clockid();
    log_time now(clock_type);
    bool monotonic = clock_type == CLOCK_MONOTONIC;

    std::string directory;
    char *file = strrchr(outputFileName, '/');
    if (!file) {
        directory = ".";
        file = outputFileName;
    } else {
        *file = '\0';
        directory = outputFileName;
        *file = '/';
        ++file;
    }
    size_t len = strlen(file);
    log_time modulo(0, NS_PER_SEC);
    std::unique_ptr<DIR, int(*)(DIR*)>dir(opendir(directory.c_str()), closedir);
    struct dirent *dp;
    while ((dp = readdir(dir.get())) != NULL) {
        if ((dp->d_type != DT_REG)
                // If we are using realtime, check all files that match the
                // basename for latest time. If we are using monotonic time
                // then only check the main file because time cycles on
                // every reboot.
                || strncmp(dp->d_name, file, len + monotonic)
                || (dp->d_name[len]
                    && ((dp->d_name[len] != '.')
                        || !isdigit(dp->d_name[len+1])))) {
            continue;
        }

        std::string file_name = directory;
        file_name += "/";
        file_name += dp->d_name;
        std::string file;
        if (!android::base::ReadFileToString(file_name, &file)) {
            continue;
        }

        bool found = false;
        for (const auto& line : android::base::Split(file, "\n")) {
            log_time t(log_time::EPOCH);
            char *ep = parseTime(t, line.c_str());
            if (!ep || (*ep != ' ')) {
                continue;
            }
            // determine the time precision of the logs (eg: msec or usec)
            for (unsigned long mod = 1UL; mod < modulo.tv_nsec; mod *= 10) {
                if (t.tv_nsec % (mod * 10)) {
                    modulo.tv_nsec = mod;
                    break;
                }
            }
            // We filter any times later than current as we may not have the
            // year stored with each log entry. Also, since it is possible for
            // entries to be recorded out of order (very rare) we select the
            // maximum we find just in case.
            if ((t < now) && (t > retval)) {
                retval = t;
                found = true;
            }
        }
        // We count on the basename file to be the definitive end, so stop here.
        if (!dp->d_name[len] && found) {
            break;
        }
    }
    if (retval == log_time::EPOCH) {
        return retval;
    }
    // tail_time prints matching or higher, round up by the modulo to prevent
    // a replay of the last entry we have just checked.
    retval += modulo;
    return retval;
}

} /* namespace android */


int main(int argc, char **argv)
{
    using namespace android;
    int err;
    int hasSetLogFormat = 0;
    int clearLog = 0;
    int getLogSize = 0;
    unsigned long setLogSize = 0;
    int getPruneList = 0;
    char *setPruneList = NULL;
    int printStatistics = 0;
    int mode = ANDROID_LOG_RDONLY;
    const char *forceFilters = NULL;
    log_device_t* devices = NULL;
    log_device_t* dev;
    bool printDividers = false;
    struct logger_list *logger_list;
    size_t tail_lines = 0;
    log_time tail_time(log_time::EPOCH);
    size_t pid = 0;
    bool got_t = false;

    signal(SIGPIPE, exit);

    g_logformat = android_log_format_new();

    if (argc == 2 && 0 == strcmp(argv[1], "--help")) {
        show_help(argv[0]);
        return EXIT_SUCCESS;
    }

    for (;;) {
        int ret;

        int option_index = 0;
        static const char pid_str[] = "pid";
        static const char wrap_str[] = "wrap";
        static const struct option long_options[] = {
          { "binary",        no_argument,       NULL,   'B' },
          { "buffer",        required_argument, NULL,   'b' },
          { "buffer-size",   optional_argument, NULL,   'g' },
          { "clear",         no_argument,       NULL,   'c' },
          { "dividers",      no_argument,       NULL,   'D' },
          { "file",          required_argument, NULL,   'f' },
          { "format",        required_argument, NULL,   'v' },
          // hidden and undocumented reserved alias for --max-count
          { "head",          required_argument, NULL,   'm' },
          { "last",          no_argument,       NULL,   'L' },
          { pid_str,         required_argument, NULL,   0 },
          { "max-count",     required_argument, NULL,   'm' },
          { "prune",         optional_argument, NULL,   'p' },
          { "regex",         required_argument, NULL,   'e' },
          { "rotate-count",  required_argument, NULL,   'n' },
          { "rotate-kbytes", required_argument, NULL,   'r' },
          { "statistics",    no_argument,       NULL,   'S' },
          // hidden and undocumented reserved alias for -t
          { "tail",          required_argument, NULL,   't' },
          // support, but ignore and do not document, the optional argument
          { wrap_str,        optional_argument, NULL,   0 },
          { NULL,            0,                 NULL,   0 }
        };

        ret = getopt_long(argc, argv, ":cdDLt:T:gG:sQf:r:n:v:b:BSpP:m:e:",
                          long_options, &option_index);

        if (ret < 0) {
            break;
        }

        switch (ret) {
            case 0:
                // One of the long options
                if (long_options[option_index].name == pid_str) {
                    // ToDo: determine runtime PID_MAX?
                    if (!getSizeTArg(optarg, &pid, 1)) {
                        logcat_panic(true, "%s %s out of range\n",
                                     long_options[option_index].name, optarg);
                    }
                    break;
                }
                if (long_options[option_index].name == wrap_str) {
                    mode |= ANDROID_LOG_WRAP |
                            ANDROID_LOG_RDONLY |
                            ANDROID_LOG_NONBLOCK;
                    // ToDo: implement API that supports setting a wrap timeout
                    size_t dummy = ANDROID_LOG_WRAP_DEFAULT_TIMEOUT;
                    if (optarg && !getSizeTArg(optarg, &dummy, 1)) {
                        logcat_panic(true, "%s %s out of range\n",
                                     long_options[option_index].name, optarg);
                    }
                    if (dummy != ANDROID_LOG_WRAP_DEFAULT_TIMEOUT) {
                        fprintf(stderr,
                                "WARNING: %s %u seconds, ignoring %zu\n",
                                long_options[option_index].name,
                                ANDROID_LOG_WRAP_DEFAULT_TIMEOUT, dummy);
                    }
                    break;
                }
            break;

            case 's':
                // default to all silent
                android_log_addFilterRule(g_logformat, "*:s");
            break;

            case 'c':
                clearLog = 1;
                mode |= ANDROID_LOG_WRONLY;
            break;

            case 'L':
                mode |= ANDROID_LOG_PSTORE;
            break;

            case 'd':
                mode |= ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK;
            break;

            case 't':
                got_t = true;
                mode |= ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK;
                /* FALLTHRU */
            case 'T':
                if (strspn(optarg, "0123456789") != strlen(optarg)) {
                    char *cp = parseTime(tail_time, optarg);
                    if (!cp) {
                        logcat_panic(false, "-%c \"%s\" not in time format\n",
                                     ret, optarg);
                    }
                    if (*cp) {
                        char c = *cp;
                        *cp = '\0';
                        fprintf(stderr,
                                "WARNING: -%c \"%s\"\"%c%s\" time truncated\n",
                                ret, optarg, c, cp + 1);
                        *cp = c;
                    }
                } else {
                    if (!getSizeTArg(optarg, &tail_lines, 1)) {
                        fprintf(stderr,
                                "WARNING: -%c %s invalid, setting to 1\n",
                                ret, optarg);
                        tail_lines = 1;
                    }
                }
            break;

            case 'D':
                printDividers = true;
            break;

            case 'e':
                g_regex = new pcrecpp::RE(optarg);
            break;

            case 'm': {
                char *end = NULL;
                if (!getSizeTArg(optarg, &g_maxCount)) {
                    logcat_panic(false, "-%c \"%s\" isn't an "
                                 "integer greater than zero\n", ret, optarg);
                }
            }
            break;

            case 'g':
                if (!optarg) {
                    getLogSize = 1;
                    break;
                }
                // FALLTHRU

            case 'G': {
                char *cp;
                if (strtoll(optarg, &cp, 0) > 0) {
                    setLogSize = strtoll(optarg, &cp, 0);
                } else {
                    setLogSize = 0;
                }

                switch(*cp) {
                case 'g':
                case 'G':
                    setLogSize *= 1024;
                /* FALLTHRU */
                case 'm':
                case 'M':
                    setLogSize *= 1024;
                /* FALLTHRU */
                case 'k':
                case 'K':
                    setLogSize *= 1024;
                /* FALLTHRU */
                case '\0':
                break;

                default:
                    setLogSize = 0;
                }

                if (!setLogSize) {
                    fprintf(stderr, "ERROR: -G <num><multiplier>\n");
                    return EXIT_FAILURE;
                }
            }
            break;

            case 'p':
                if (!optarg) {
                    getPruneList = 1;
                    break;
                }
                // FALLTHRU

            case 'P':
                setPruneList = optarg;
            break;

            case 'b': {
                if (strcmp(optarg, "default") == 0) {
                    for (int i = LOG_ID_MIN; i < LOG_ID_MAX; ++i) {
                        switch (i) {
                        case LOG_ID_SECURITY:
                        case LOG_ID_EVENTS:
                            continue;
                        case LOG_ID_MAIN:
                        case LOG_ID_SYSTEM:
                        case LOG_ID_CRASH:
                            break;
                        default:
                            continue;
                        }

                        const char *name = android_log_id_to_name((log_id_t)i);
                        log_id_t log_id = android_name_to_log_id(name);

                        if (log_id != (log_id_t)i) {
                            continue;
                        }

                        bool found = false;
                        for (dev = devices; dev; dev = dev->next) {
                            if (!strcmp(optarg, dev->device)) {
                                found = true;
                                break;
                            }
                            if (!dev->next) {
                                break;
                            }
                        }
                        if (found) {
                            break;
                        }

                        log_device_t* d = new log_device_t(name, false);

                        if (dev) {
                            dev->next = d;
                            dev = d;
                        } else {
                            devices = dev = d;
                        }
                        g_devCount++;
                    }
                    break;
                }

                if (strcmp(optarg, "all") == 0) {
                    for (int i = LOG_ID_MIN; i < LOG_ID_MAX; ++i) {
                        const char *name = android_log_id_to_name((log_id_t)i);
                        log_id_t log_id = android_name_to_log_id(name);

                        if (log_id != (log_id_t)i) {
                            continue;
                        }

                        bool found = false;
                        for (dev = devices; dev; dev = dev->next) {
                            if (!strcmp(optarg, dev->device)) {
                                found = true;
                                break;
                            }
                            if (!dev->next) {
                                break;
                            }
                        }
                        if (found) {
                            break;
                        }

                        bool binary = !strcmp(name, "events") ||
                                      !strcmp(name, "security");
                        log_device_t* d = new log_device_t(name, binary);

                        if (dev) {
                            dev->next = d;
                            dev = d;
                        } else {
                            devices = dev = d;
                        }
                        g_devCount++;
                    }
                    break;
                }

                bool binary = !(strcmp(optarg, "events") &&
                                strcmp(optarg, "security"));

                if (devices) {
                    dev = devices;
                    while (dev->next) {
                        if (!strcmp(optarg, dev->device)) {
                            dev = NULL;
                            break;
                        }
                        dev = dev->next;
                    }
                    if (dev) {
                        dev->next = new log_device_t(optarg, binary);
                    }
                } else {
                    devices = new log_device_t(optarg, binary);
                }
                g_devCount++;
            }
            break;

            case 'B':
                g_printBinary = 1;
            break;

            case 'f':
                if ((tail_time == log_time::EPOCH) && (tail_lines == 0)) {
                    tail_time = lastLogTime(optarg);
                }
                // redirect output to a file
                g_outputFileName = optarg;
            break;

            case 'r':
                if (!getSizeTArg(optarg, &g_logRotateSizeKBytes, 1)) {
                    logcat_panic(true, "Invalid parameter %s to -r\n", optarg);
                }
            break;

            case 'n':
                if (!getSizeTArg(optarg, &g_maxRotatedLogs, 1)) {
                    logcat_panic(true, "Invalid parameter %s to -n\n", optarg);
                }
            break;

            case 'v':
                err = setLogFormat (optarg);
                if (err < 0) {
                    logcat_panic(true, "Invalid parameter %s to -v\n", optarg);
                }
                hasSetLogFormat |= err;
            break;

            case 'Q':
                /* this is a *hidden* option used to start a version of logcat                 */
                /* in an emulated device only. it basically looks for androidboot.logcat=      */
                /* on the kernel command line. If something is found, it extracts a log filter */
                /* and uses it to run the program. If nothing is found, the program should     */
                /* quit immediately                                                            */
#define  KERNEL_OPTION  "androidboot.logcat="
#define  CONSOLE_OPTION "androidboot.console="
                {
                    int          fd;
                    char*        logcat;
                    char*        console;
                    int          force_exit = 1;
                    static char  cmdline[1024];

                    fd = open("/proc/cmdline", O_RDONLY);
                    if (fd >= 0) {
                        int  n = read(fd, cmdline, sizeof(cmdline)-1 );
                        if (n < 0) n = 0;
                        cmdline[n] = 0;
                        close(fd);
                    } else {
                        cmdline[0] = 0;
                    }

                    logcat  = strstr( cmdline, KERNEL_OPTION );
                    console = strstr( cmdline, CONSOLE_OPTION );
                    if (logcat != NULL) {
                        char*  p = logcat + sizeof(KERNEL_OPTION)-1;;
                        char*  q = strpbrk( p, " \t\n\r" );;

                        if (q != NULL)
                            *q = 0;

                        forceFilters = p;
                        force_exit   = 0;
                    }
                    /* if nothing found or invalid filters, exit quietly */
                    if (force_exit) {
                        return EXIT_SUCCESS;
                    }

                    /* redirect our output to the emulator console */
                    if (console) {
                        char*  p = console + sizeof(CONSOLE_OPTION)-1;
                        char*  q = strpbrk( p, " \t\n\r" );
                        char   devname[64];
                        int    len;

                        if (q != NULL) {
                            len = q - p;
                        } else
                            len = strlen(p);

                        len = snprintf( devname, sizeof(devname), "/dev/%.*s", len, p );
                        fprintf(stderr, "logcat using %s (%d)\n", devname, len);
                        if (len < (int)sizeof(devname)) {
                            fd = open( devname, O_WRONLY );
                            if (fd >= 0) {
                                dup2(fd, 1);
                                dup2(fd, 2);
                                close(fd);
                            }
                        }
                    }
                }
                break;

            case 'S':
                printStatistics = 1;
                break;

            case ':':
                logcat_panic(true, "Option -%c needs an argument\n", optopt);
                break;

            default:
                logcat_panic(true, "Unrecognized Option %c\n", optopt);
                break;
        }
    }

    if (g_maxCount && got_t) {
        logcat_panic(true, "Cannot use -m (--max-count) and -t together\n");
    }

    if (!devices) {
        dev = devices = new log_device_t("main", false);
        g_devCount = 1;
        if (android_name_to_log_id("system") == LOG_ID_SYSTEM) {
            dev = dev->next = new log_device_t("system", false);
            g_devCount++;
        }
        if (android_name_to_log_id("crash") == LOG_ID_CRASH) {
            dev = dev->next = new log_device_t("crash", false);
            g_devCount++;
        }
    }

    if (g_logRotateSizeKBytes != 0 && g_outputFileName == NULL) {
        logcat_panic(true, "-r requires -f as well\n");
    }

    setupOutput();

    if (hasSetLogFormat == 0) {
        const char* logFormat = getenv("ANDROID_PRINTF_LOG");

        if (logFormat != NULL) {
            err = setLogFormat(logFormat);
            if (err < 0) {
                fprintf(stderr, "invalid format in ANDROID_PRINTF_LOG '%s'\n",
                                    logFormat);
            }
        } else {
            setLogFormat("threadtime");
        }
    }

    if (forceFilters) {
        err = android_log_addFilterString(g_logformat, forceFilters);
        if (err < 0) {
            logcat_panic(false, "Invalid filter expression in logcat args\n");
        }
    } else if (argc == optind) {
        // Add from environment variable
        char *env_tags_orig = getenv("ANDROID_LOG_TAGS");

        if (env_tags_orig != NULL) {
            err = android_log_addFilterString(g_logformat, env_tags_orig);

            if (err < 0) {
                logcat_panic(true,
                            "Invalid filter expression in ANDROID_LOG_TAGS\n");
            }
        }
    } else {
        // Add from commandline
        for (int i = optind ; i < argc ; i++) {
            err = android_log_addFilterString(g_logformat, argv[i]);

            if (err < 0) {
                logcat_panic(true, "Invalid filter expression '%s'\n", argv[i]);
            }
        }
    }

    dev = devices;
    if (tail_time != log_time::EPOCH) {
        logger_list = android_logger_list_alloc_time(mode, tail_time, pid);
    } else {
        logger_list = android_logger_list_alloc(mode, tail_lines, pid);
    }
    const char *openDeviceFail = NULL;
    const char *clearFail = NULL;
    const char *setSizeFail = NULL;
    const char *getSizeFail = NULL;
    // We have three orthogonal actions below to clear, set log size and
    // get log size. All sharing the same iteration loop.
    while (dev) {
        dev->logger_list = logger_list;
        dev->logger = android_logger_open(logger_list,
                                          android_name_to_log_id(dev->device));
        if (!dev->logger) {
            openDeviceFail = openDeviceFail ?: dev->device;
            dev = dev->next;
            continue;
        }

        if (clearLog) {
            if (android_logger_clear(dev->logger)) {
                clearFail = clearFail ?: dev->device;
            }
        }

        if (setLogSize) {
            if (android_logger_set_log_size(dev->logger, setLogSize)) {
                setSizeFail = setSizeFail ?: dev->device;
            }
        }

        if (getLogSize) {
            long size = android_logger_get_log_size(dev->logger);
            long readable = android_logger_get_log_readable_size(dev->logger);

            if ((size < 0) || (readable < 0)) {
                getSizeFail = getSizeFail ?: dev->device;
            } else {
                printf("%s: ring buffer is %ld%sb (%ld%sb consumed), "
                       "max entry is %db, max payload is %db\n", dev->device,
                       value_of_size(size), multiplier_of_size(size),
                       value_of_size(readable), multiplier_of_size(readable),
                       (int) LOGGER_ENTRY_MAX_LEN,
                       (int) LOGGER_ENTRY_MAX_PAYLOAD);
            }
        }

        dev = dev->next;
    }
    // report any errors in the above loop and exit
    if (openDeviceFail) {
        logcat_panic(false, "Unable to open log device '%s'\n", openDeviceFail);
    }
    if (clearFail) {
        logcat_panic(false, "failed to clear the '%s' log\n", clearFail);
    }
    if (setSizeFail) {
        logcat_panic(false, "failed to set the '%s' log size\n", setSizeFail);
    }
    if (getSizeFail) {
        logcat_panic(false, "failed to get the readable '%s' log size",
                     getSizeFail);
    }

    if (setPruneList) {
        size_t len = strlen(setPruneList);
        /*extra 32 bytes are needed by  android_logger_set_prune_list */
        size_t bLen = len + 32;
        char *buf = NULL;
        if (asprintf(&buf, "%-*s", (int)(bLen - 1), setPruneList) > 0) {
            buf[len] = '\0';
            if (android_logger_set_prune_list(logger_list, buf, bLen)) {
                logcat_panic(false, "failed to set the prune list");
            }
            free(buf);
        } else {
            logcat_panic(false, "failed to set the prune list (alloc)");
        }
    }

    if (printStatistics || getPruneList) {
        size_t len = 8192;
        char *buf;

        for (int retry = 32;
                (retry >= 0) && ((buf = new char [len]));
                delete [] buf, buf = NULL, --retry) {
            if (getPruneList) {
                android_logger_get_prune_list(logger_list, buf, len);
            } else {
                android_logger_get_statistics(logger_list, buf, len);
            }
            buf[len-1] = '\0';
            if (atol(buf) < 3) {
                delete [] buf;
                buf = NULL;
                break;
            }
            size_t ret = atol(buf) + 1;
            if (ret <= len) {
                len = ret;
                break;
            }
            len = ret;
        }

        if (!buf) {
            logcat_panic(false, "failed to read data");
        }

        // remove trailing FF
        char *cp = buf + len - 1;
        *cp = '\0';
        bool truncated = *--cp != '\f';
        if (!truncated) {
            *cp = '\0';
        }

        // squash out the byte count
        cp = buf;
        if (!truncated) {
            while (isdigit(*cp)) {
                ++cp;
            }
            if (*cp == '\n') {
                ++cp;
            }
        }

        printf("%s", cp);
        delete [] buf;
        return EXIT_SUCCESS;
    }


    if (getLogSize) {
        return EXIT_SUCCESS;
    }
    if (setLogSize || setPruneList) {
        return EXIT_SUCCESS;
    }
    if (clearLog) {
        return EXIT_SUCCESS;
    }

    //LOG_EVENT_INT(10, 12345);
    //LOG_EVENT_LONG(11, 0x1122334455667788LL);
    //LOG_EVENT_STRING(0, "whassup, doc?");

    dev = NULL;
    log_device_t unexpected("unexpected", false);

    while (!g_maxCount || (g_printCount < g_maxCount)) {
        struct log_msg log_msg;
        log_device_t* d;
        int ret = android_logger_list_read(logger_list, &log_msg);

        if (ret == 0) {
            logcat_panic(false, "read: unexpected EOF!\n");
        }

        if (ret < 0) {
            if (ret == -EAGAIN) {
                break;
            }

            if (ret == -EIO) {
                logcat_panic(false, "read: unexpected EOF!\n");
            }
            if (ret == -EINVAL) {
                logcat_panic(false, "read: unexpected length.\n");
            }
            logcat_panic(false, "logcat read failure");
        }

        for (d = devices; d; d = d->next) {
            if (android_name_to_log_id(d->device) == log_msg.id()) {
                break;
            }
        }
        if (!d) {
            g_devCount = 2; // set to Multiple
            d = &unexpected;
            d->binary = log_msg.id() == LOG_ID_EVENTS;
        }

        if (dev != d) {
            dev = d;
            maybePrintStart(dev, printDividers);
        }
        if (g_printBinary) {
            printBinary(&log_msg);
        } else {
            processBuffer(dev, &log_msg);
        }
    }

    android_logger_list_free(logger_list);

    return EXIT_SUCCESS;
}
