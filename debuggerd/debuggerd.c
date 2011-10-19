/* system/debuggerd/debuggerd.c
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/exec_elf.h>
#include <sys/stat.h>

#include <cutils/sockets.h>
#include <cutils/logd.h>
#include <cutils/logger.h>
#include <cutils/properties.h>

#include <linux/input.h>

#include <private/android_filesystem_config.h>

#include "debuggerd.h"
#include "utility.h"

#define ANDROID_LOG_INFO 4

void _LOG(int tfd, bool in_tombstone_only, const char *fmt, ...)
    __attribute__ ((format(printf, 3, 4)));

/* Log information onto the tombstone */
void _LOG(int tfd, bool in_tombstone_only, const char *fmt, ...)
{
    char buf[512];

    va_list ap;
    va_start(ap, fmt);

    if (tfd >= 0) {
        int len;
        vsnprintf(buf, sizeof(buf), fmt, ap);
        len = strlen(buf);
        if(tfd >= 0) write(tfd, buf, len);
    }

    if (!in_tombstone_only)
        __android_log_vprint(ANDROID_LOG_INFO, "DEBUG", fmt, ap);
    va_end(ap);
}

// 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /system/lib/libcomposer.so
// 012345678901234567890123456789012345678901234567890123456789
// 0         1         2         3         4         5

mapinfo *parse_maps_line(char *line)
{
    mapinfo *mi;
    int len = strlen(line);

    if (len < 1) return 0;      /* not expected */
    line[--len] = 0;

    if (len < 50) {
        mi = malloc(sizeof(mapinfo) + 1);
    } else {
        mi = malloc(sizeof(mapinfo) + (len - 47));
    }
    if (mi == 0) return 0;

    mi->isExecutable = (line[20] == 'x');

    mi->start = strtoul(line, 0, 16);
    mi->end = strtoul(line + 9, 0, 16);
    /* To be filled in parse_elf_info if the mapped section starts with
     * elf_header
     */
    mi->exidx_start = mi->exidx_end = 0;
    mi->symbols = 0;
    mi->next = 0;
    if (len < 50) {
        mi->name[0] = '\0';
    } else {
        strcpy(mi->name, line + 49);
    }

    return mi;
}

void dump_build_info(int tfd)
{
    char fingerprint[PROPERTY_VALUE_MAX];

    property_get("ro.build.fingerprint", fingerprint, "unknown");

    _LOG(tfd, false, "Build fingerprint: '%s'\n", fingerprint);
}

const char *get_signame(int sig)
{
    switch(sig) {
    case SIGILL:     return "SIGILL";
    case SIGABRT:    return "SIGABRT";
    case SIGBUS:     return "SIGBUS";
    case SIGFPE:     return "SIGFPE";
    case SIGSEGV:    return "SIGSEGV";
    case SIGSTKFLT:  return "SIGSTKFLT";
    default:         return "?";
    }
}

const char *get_sigcode(int signo, int code)
{
    switch (signo) {
    case SIGILL:
        switch (code) {
        case ILL_ILLOPC: return "ILL_ILLOPC";
        case ILL_ILLOPN: return "ILL_ILLOPN";
        case ILL_ILLADR: return "ILL_ILLADR";
        case ILL_ILLTRP: return "ILL_ILLTRP";
        case ILL_PRVOPC: return "ILL_PRVOPC";
        case ILL_PRVREG: return "ILL_PRVREG";
        case ILL_COPROC: return "ILL_COPROC";
        case ILL_BADSTK: return "ILL_BADSTK";
        }
        break;
    case SIGBUS:
        switch (code) {
        case BUS_ADRALN: return "BUS_ADRALN";
        case BUS_ADRERR: return "BUS_ADRERR";
        case BUS_OBJERR: return "BUS_OBJERR";
        }
        break;
    case SIGFPE:
        switch (code) {
        case FPE_INTDIV: return "FPE_INTDIV";
        case FPE_INTOVF: return "FPE_INTOVF";
        case FPE_FLTDIV: return "FPE_FLTDIV";
        case FPE_FLTOVF: return "FPE_FLTOVF";
        case FPE_FLTUND: return "FPE_FLTUND";
        case FPE_FLTRES: return "FPE_FLTRES";
        case FPE_FLTINV: return "FPE_FLTINV";
        case FPE_FLTSUB: return "FPE_FLTSUB";
        }
        break;
    case SIGSEGV:
        switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
        }
        break;
    }
    return "?";
}

void dump_fault_addr(int tfd, int pid, int sig)
{
    siginfo_t si;

    memset(&si, 0, sizeof(si));
    if(ptrace(PTRACE_GETSIGINFO, pid, 0, &si)){
        _LOG(tfd, false, "cannot get siginfo: %s\n", strerror(errno));
    } else if (signal_has_address(sig)) {
        _LOG(tfd, false, "signal %d (%s), code %d (%s), fault addr %08x\n",
             sig, get_signame(sig),
             si.si_code, get_sigcode(sig, si.si_code),
             (uintptr_t) si.si_addr);
    } else {
        _LOG(tfd, false, "signal %d (%s), code %d (%s), fault addr --------\n",
             sig, get_signame(sig), si.si_code, get_sigcode(sig, si.si_code));
    }
}

void dump_crash_banner(int tfd, unsigned pid, unsigned tid, int sig)
{
    char data[1024];
    char *x = 0;
    FILE *fp;

    sprintf(data, "/proc/%d/cmdline", pid);
    fp = fopen(data, "r");
    if(fp) {
        x = fgets(data, 1024, fp);
        fclose(fp);
    }

    _LOG(tfd, false,
         "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
    dump_build_info(tfd);
    _LOG(tfd, false, "pid: %d, tid: %d  >>> %s <<<\n",
         pid, tid, x ? x : "UNKNOWN");

    if(sig) dump_fault_addr(tfd, tid, sig);
}

static void parse_elf_info(mapinfo *milist, pid_t pid)
{
    mapinfo *mi;
    for (mi = milist; mi != NULL; mi = mi->next) {
        if (!mi->isExecutable)
            continue;

        Elf32_Ehdr ehdr;

        memset(&ehdr, 0, sizeof(Elf32_Ehdr));
        /* Read in sizeof(Elf32_Ehdr) worth of data from the beginning of
         * mapped section.
         */
        get_remote_struct(pid, (void *) (mi->start), &ehdr,
                          sizeof(Elf32_Ehdr));
        /* Check if it has the matching magic words */
        if (IS_ELF(ehdr)) {
            Elf32_Phdr phdr;
            Elf32_Phdr *ptr;
            int i;

            ptr = (Elf32_Phdr *) (mi->start + ehdr.e_phoff);
            for (i = 0; i < ehdr.e_phnum; i++) {
                /* Parse the program header */
                get_remote_struct(pid, (char *) (ptr+i), &phdr,
                                  sizeof(Elf32_Phdr));
#ifdef __arm__
                /* Found a EXIDX segment? */
                if (phdr.p_type == PT_ARM_EXIDX) {
                    mi->exidx_start = mi->start + phdr.p_offset;
                    mi->exidx_end = mi->exidx_start + phdr.p_filesz;
                    break;
                }
#endif
            }

            /* Try to load symbols from this file */
            mi->symbols = symbol_table_create(mi->name);
        }
    }
}

void dump_crash_report(int tfd, unsigned pid, unsigned tid, bool at_fault)
{
    char data[1024];
    FILE *fp;
    mapinfo *milist = 0;
    unsigned int sp_list[STACK_CONTENT_DEPTH];
    int stack_depth;
#ifdef __arm__
    int frame0_pc_sane = 1;
#endif

    if (!at_fault) {
        _LOG(tfd, true,
         "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
        _LOG(tfd, true, "pid: %d, tid: %d\n", pid, tid);
    }

    dump_registers(tfd, tid, at_fault);

    /* Clear stack pointer records */
    memset(sp_list, 0, sizeof(sp_list));

    sprintf(data, "/proc/%d/maps", pid);
    fp = fopen(data, "r");
    if(fp) {
        while(fgets(data, 1024, fp)) {
            mapinfo *mi = parse_maps_line(data);
            if(mi) {
                mi->next = milist;
                milist = mi;
            }
        }
        fclose(fp);
    }

    parse_elf_info(milist, tid);

#if __arm__
    /* If stack unwinder fails, use the default solution to dump the stack
     * content.
     */
    stack_depth = unwind_backtrace_with_ptrace(tfd, tid, milist, sp_list,
                                               &frame0_pc_sane, at_fault);

    /* The stack unwinder should at least unwind two levels of stack. If less
     * level is seen we make sure at lease pc and lr are dumped.
     */
    if (stack_depth < 2) {
        dump_pc_and_lr(tfd, tid, milist, stack_depth, at_fault);
    }

    dump_stack_and_code(tfd, tid, milist, stack_depth, sp_list, at_fault);
#elif __i386__
    /* If stack unwinder fails, use the default solution to dump the stack
    * content.
    */
    stack_depth = unwind_backtrace_with_ptrace_x86(tfd, tid, milist,at_fault);
#else
#error "Unsupported architecture"
#endif

    while(milist) {
        mapinfo *next = milist->next;
        symbol_table_free(milist->symbols);
        free(milist);
        milist = next;
    }
}

#define MAX_TOMBSTONES	10

#define typecheck(x,y) {    \
    typeof(x) __dummy1;     \
    typeof(y) __dummy2;     \
    (void)(&__dummy1 == &__dummy2); }

#define TOMBSTONE_DIR	"/data/tombstones"

/*
 * find_and_open_tombstone - find an available tombstone slot, if any, of the
 * form tombstone_XX where XX is 00 to MAX_TOMBSTONES-1, inclusive. If no
 * file is available, we reuse the least-recently-modified file.
 */
static int find_and_open_tombstone(void)
{
    unsigned long mtime = ULONG_MAX;
    struct stat sb;
    char path[128];
    int fd, i, oldest = 0;

    /*
     * XXX: Our stat.st_mtime isn't time_t. If it changes, as it probably ought
     * to, our logic breaks. This check will generate a warning if that happens.
     */
    typecheck(mtime, sb.st_mtime);

    /*
     * In a single wolf-like pass, find an available slot and, in case none
     * exist, find and record the least-recently-modified file.
     */
    for (i = 0; i < MAX_TOMBSTONES; i++) {
        snprintf(path, sizeof(path), TOMBSTONE_DIR"/tombstone_%02d", i);

        if (!stat(path, &sb)) {
            if (sb.st_mtime < mtime) {
                oldest = i;
                mtime = sb.st_mtime;
            }
            continue;
        }
        if (errno != ENOENT)
            continue;

        fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0)
            continue;	/* raced ? */

        fchown(fd, AID_SYSTEM, AID_SYSTEM);
        return fd;
    }

    /* we didn't find an available file, so we clobber the oldest one */
    snprintf(path, sizeof(path), TOMBSTONE_DIR"/tombstone_%02d", oldest);
    fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    fchown(fd, AID_SYSTEM, AID_SYSTEM);

    return fd;
}

/* Return true if some thread is not detached cleanly */
static bool dump_sibling_thread_report(int tfd, unsigned pid, unsigned tid)
{
    char task_path[1024];

    sprintf(task_path, "/proc/%d/task", pid);
    DIR *d;
    struct dirent *de;
    int need_cleanup = 0;

    d = opendir(task_path);
    /* Bail early if cannot open the task directory */
    if (d == NULL) {
        XLOG("Cannot open /proc/%d/task\n", pid);
        return false;
    }
    while ((de = readdir(d)) != NULL) {
        unsigned new_tid;
        /* Ignore "." and ".." */
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        new_tid = atoi(de->d_name);
        /* The main thread at fault has been handled individually */
        if (new_tid == tid)
            continue;

        /* Skip this thread if cannot ptrace it */
        if (ptrace(PTRACE_ATTACH, new_tid, 0, 0) < 0)
            continue;

        dump_crash_report(tfd, pid, new_tid, false);

        if (ptrace(PTRACE_DETACH, new_tid, 0, 0) != 0) {
            XLOG("detach of tid %d failed: %s\n", new_tid, strerror(errno));
            need_cleanup = 1;
        }
    }
    closedir(d);

    return need_cleanup != 0;
}

/*
 * Reads the contents of the specified log device, filters out the entries
 * that don't match the specified pid, and writes them to the tombstone file.
 *
 * If "tailOnly" is set, we only print the last few lines.
 */
static void dump_log_file(int tfd, unsigned pid, const char* filename,
    bool tailOnly)
{
    bool first = true;

    /* circular buffer, for "tailOnly" mode */
    const int kShortLogMaxLines = 5;
    const int kShortLogLineLen = 256;
    char shortLog[kShortLogMaxLines][kShortLogLineLen];
    int shortLogCount = 0;
    int shortLogNext = 0;

    int logfd = open(filename, O_RDONLY | O_NONBLOCK);
    if (logfd < 0) {
        XLOG("Unable to open %s: %s\n", filename, strerror(errno));
        return;
    }

    union {
        unsigned char buf[LOGGER_ENTRY_MAX_LEN + 1];
        struct logger_entry entry;
    } log_entry;

    while (true) {
        ssize_t actual = read(logfd, log_entry.buf, LOGGER_ENTRY_MAX_LEN);
        if (actual < 0) {
            if (errno == EINTR) {
                /* interrupted by signal, retry */
                continue;
            } else if (errno == EAGAIN) {
                /* non-blocking EOF; we're done */
                break;
            } else {
                _LOG(tfd, true, "Error while reading log: %s\n",
                    strerror(errno));
                break;
            }
        } else if (actual == 0) {
            _LOG(tfd, true, "Got zero bytes while reading log: %s\n",
                strerror(errno));
            break;
        }

        /*
         * NOTE: if you XLOG something here, this will spin forever,
         * because you will be writing as fast as you're reading.  Any
         * high-frequency debug diagnostics should just be written to
         * the tombstone file.
         */

        struct logger_entry* entry = &log_entry.entry;

        if (entry->pid != (int32_t) pid) {
            /* wrong pid, ignore */
            continue;
        }

        if (first) {
            _LOG(tfd, true, "--------- %slog %s\n",
                tailOnly ? "tail end of " : "", filename);
            first = false;
        }

        /*
         * Msg format is: <priority:1><tag:N>\0<message:N>\0
         *
         * We want to display it in the same format as "logcat -v threadtime"
         * (although in this case the pid is redundant).
         *
         * TODO: scan for line breaks ('\n') and display each text line
         * on a separate line, prefixed with the header, like logcat does.
         */
        static const char* kPrioChars = "!.VDIWEFS";
        unsigned char prio = entry->msg[0];
        char* tag = entry->msg + 1;
        char* msg = tag + strlen(tag) + 1;

        /* consume any trailing newlines */
        char* eatnl = msg + strlen(msg) - 1;
        while (eatnl >= msg && *eatnl == '\n') {
            *eatnl-- = '\0';
        }

        char prioChar = (prio < strlen(kPrioChars) ? kPrioChars[prio] : '?');

        char timeBuf[32];
        time_t sec = (time_t) entry->sec;
        struct tm tmBuf;
        struct tm* ptm;
        ptm = localtime_r(&sec, &tmBuf);
        strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);

        if (tailOnly) {
            snprintf(shortLog[shortLogNext], kShortLogLineLen,
                "%s.%03d %5d %5d %c %-8s: %s",
                timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
                prioChar, tag, msg);
            shortLogNext = (shortLogNext + 1) % kShortLogMaxLines;
            shortLogCount++;
        } else {
            _LOG(tfd, true, "%s.%03d %5d %5d %c %-8s: %s\n",
                timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
                prioChar, tag, msg);
        }
    }

    if (tailOnly) {
        int i;

        /*
         * If we filled the buffer, we want to start at "next", which has
         * the oldest entry.  If we didn't, we want to start at zero.
         */
        if (shortLogCount < kShortLogMaxLines) {
            shortLogNext = 0;
        } else {
            shortLogCount = kShortLogMaxLines;  /* cap at window size */
        }

        for (i = 0; i < shortLogCount; i++) {
            _LOG(tfd, true, "%s\n", shortLog[shortLogNext]);
            shortLogNext = (shortLogNext + 1) % kShortLogMaxLines;
        }
    }

    close(logfd);
}

/*
 * Dumps the logs generated by the specified pid to the tombstone, from both
 * "system" and "main" log devices.  Ideally we'd interleave the output.
 */
static void dump_logs(int tfd, unsigned pid, bool tailOnly)
{
    dump_log_file(tfd, pid, "/dev/log/system", tailOnly);
    dump_log_file(tfd, pid, "/dev/log/main", tailOnly);
}

/* Return true if some thread is not detached cleanly */
static bool engrave_tombstone(unsigned pid, unsigned tid, int debug_uid,
                              int signal)
{
    int fd;
    bool need_cleanup = false;

    /* don't copy log messages to tombstone unless this is a dev device */
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.debuggable", value, "0");
    bool wantLogs = (value[0] == '1');

    mkdir(TOMBSTONE_DIR, 0755);
    chown(TOMBSTONE_DIR, AID_SYSTEM, AID_SYSTEM);

    fd = find_and_open_tombstone();
    if (fd < 0)
        return need_cleanup;

    dump_crash_banner(fd, pid, tid, signal);
    dump_crash_report(fd, pid, tid, true);

    if (wantLogs) {
        dump_logs(fd, pid, true);
    }

    /*
     * If the user has requested to attach gdb, don't collect the per-thread
     * information as it increases the chance to lose track of the process.
     */
    if ((signed)pid > debug_uid) {
        need_cleanup = dump_sibling_thread_report(fd, pid, tid);
    }

    if (wantLogs) {
        dump_logs(fd, pid, false);
    }

    close(fd);
    return need_cleanup;
}

static int
write_string(const char* file, const char* string)
{
    int len;
    int fd;
    ssize_t amt;
    fd = open(file, O_RDWR);
    len = strlen(string);
    if (fd < 0)
        return -errno;
    amt = write(fd, string, len);
    close(fd);
    return amt >= 0 ? 0 : -errno;
}

static
void init_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "0");
    write_string("/sys/class/leds/green/brightness", "0");
    write_string("/sys/class/leds/blue/brightness", "0");
    write_string("/sys/class/leds/red/device/blink", "0");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "0,0");
}

static
void enable_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "255");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "1,0");
}

static
void disable_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "0");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "0,0");
}

extern int init_getevent();
extern void uninit_getevent();
extern int get_event(struct input_event* event, int timeout);

static void wait_for_user_action(unsigned tid, struct ucred* cr)
{
    (void)tid;
    /* First log a helpful message */
    LOG(    "********************************************************\n"
            "* Process %d has been suspended while crashing.  To\n"
            "* attach gdbserver for a gdb connection on port 5039:\n"
            "*\n"
            "*     adb shell gdbserver :5039 --attach %d &\n"
            "*\n"
            "* Press HOME key to let the process continue crashing.\n"
            "********************************************************\n",
            cr->pid, cr->pid);

    /* wait for HOME key (TODO: something useful for devices w/o HOME key) */
    if (init_getevent() == 0) {
        int ms = 1200 / 10;
        int dit = 1;
        int dah = 3*dit;
        int _       = -dit;
        int ___     = 3*_;
        int _______ = 7*_;
        const signed char codes[] = {
           dit,_,dit,_,dit,___,dah,_,dah,_,dah,___,dit,_,dit,_,dit,_______
        };
        size_t s = 0;
        struct input_event e;
        int home = 0;
        init_debug_led();
        enable_debug_led();
        do {
            int timeout = abs((int)(codes[s])) * ms;
            int res = get_event(&e, timeout);
            if (res == 0) {
                if (e.type==EV_KEY && e.code==KEY_HOME && e.value==0)
                    home = 1;
            } else if (res == 1) {
                if (++s >= sizeof(codes)/sizeof(*codes))
                    s = 0;
                if (codes[s] > 0) {
                    enable_debug_led();
                } else {
                    disable_debug_led();
                }
            }
        } while (!home);
        uninit_getevent();
    }

    /* don't forget to turn debug led off */
    disable_debug_led();

    /* close filedescriptor */
    LOG("debuggerd resuming process %d", cr->pid);
 }

static void handle_crashing_process(int fd)
{
    char buf[64];
    struct stat s;
    unsigned tid;
    struct ucred cr;
    int n, len, status;
    int tid_attach_status = -1;
    unsigned retry = 30;
    bool need_cleanup = false;

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.db.uid", value, "-1");
    int debug_uid = atoi(value);

    XLOG("handle_crashing_process(%d)\n", fd);

    len = sizeof(cr);
    n = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len);
    if(n != 0) {
        LOG("cannot get credentials\n");
        goto done;
    }

    XLOG("reading tid\n");
    fcntl(fd, F_SETFL, O_NONBLOCK);
    while((n = read(fd, &tid, sizeof(unsigned))) != sizeof(unsigned)) {
        if(errno == EINTR) continue;
        if(errno == EWOULDBLOCK) {
            if(retry-- > 0) {
                usleep(100 * 1000);
                continue;
            }
            LOG("timed out reading tid\n");
            goto done;
        }
        LOG("read failure? %s\n", strerror(errno));
        goto done;
    }

    snprintf(buf, sizeof buf, "/proc/%d/task/%d", cr.pid, tid);
    if(stat(buf, &s)) {
        LOG("tid %d does not exist in pid %d. ignoring debug request\n",
            tid, cr.pid);
        close(fd);
        return;
    }

    XLOG("BOOM: pid=%d uid=%d gid=%d tid=%d\n", cr.pid, cr.uid, cr.gid, tid);

    /* Note that at this point, the target thread's signal handler
     * is blocked in a read() call. This gives us the time to PTRACE_ATTACH
     * to it before it has a chance to really fault.
     *
     * The PTRACE_ATTACH sends a SIGSTOP to the target process, but it
     * won't necessarily have stopped by the time ptrace() returns.  (We
     * currently assume it does.)  We write to the file descriptor to
     * ensure that it can run as soon as we call PTRACE_CONT below.
     * See details in bionic/libc/linker/debugger.c, in function
     * debugger_signal_handler().
     */
    tid_attach_status = ptrace(PTRACE_ATTACH, tid, 0, 0);
    int ptrace_error = errno;

    if (TEMP_FAILURE_RETRY(write(fd, &tid, 1)) != 1) {
        XLOG("failed responding to client: %s\n",
            strerror(errno));
        goto done;
    }

    if(tid_attach_status < 0) {
        LOG("ptrace attach failed: %s\n", strerror(ptrace_error));
        goto done;
    }

    close(fd);
    fd = -1;

    const int sleep_time_usec = 200000;         /* 0.2 seconds */
    const int max_total_sleep_usec = 3000000;   /* 3 seconds */
    int loop_limit = max_total_sleep_usec / sleep_time_usec;
    for(;;) {
        if (loop_limit-- == 0) {
            LOG("timed out waiting for pid=%d tid=%d uid=%d to die\n",
                cr.pid, tid, cr.uid);
            goto done;
        }
        n = waitpid(tid, &status, __WALL | WNOHANG);

        if (n == 0) {
            /* not ready yet */
            XLOG("not ready yet\n");
            usleep(sleep_time_usec);
            continue;
        }

        if(n < 0) {
            if(errno == EAGAIN) continue;
            LOG("waitpid failed: %s\n", strerror(errno));
            goto done;
        }

        XLOG("waitpid: n=%d status=%08x\n", n, status);

        if(WIFSTOPPED(status)){
            n = WSTOPSIG(status);
            switch(n) {
            case SIGSTOP:
                XLOG("stopped -- continuing\n");
                n = ptrace(PTRACE_CONT, tid, 0, 0);
                if(n) {
                    LOG("ptrace failed: %s\n", strerror(errno));
                    goto done;
                }
                continue;

            case SIGILL:
            case SIGABRT:
            case SIGBUS:
            case SIGFPE:
            case SIGSEGV:
            case SIGSTKFLT: {
                XLOG("stopped -- fatal signal\n");
                need_cleanup = engrave_tombstone(cr.pid, tid, debug_uid, n);
                kill(tid, SIGSTOP);
                goto done;
            }

            default:
                XLOG("stopped -- unexpected signal\n");
                goto done;
            }
        } else {
            XLOG("unexpected waitpid response\n");
            goto done;
        }
    }

done:
    XLOG("detaching\n");

    /* stop the process so we can debug */
    kill(cr.pid, SIGSTOP);

    /*
     * If a thread has been attached by ptrace, make sure it is detached
     * successfully otherwise we will get a zombie.
     */
    if (tid_attach_status == 0) {
        int detach_status;
        /* detach so we can attach gdbserver */
        detach_status = ptrace(PTRACE_DETACH, tid, 0, 0);
        need_cleanup |= (detach_status != 0);
    }

    /*
     * if debug.db.uid is set, its value indicates if we should wait
     * for user action for the crashing process.
     * in this case, we log a message and turn the debug LED on
     * waiting for a gdb connection (for instance)
     */

    if ((signed)cr.uid <= debug_uid) {
        wait_for_user_action(tid, &cr);
    }

    /*
     * Resume stopped process (so it can crash in peace).  If we didn't
     * successfully detach, we're still the parent, and the actual parent
     * won't receive a death notification via wait(2).  At this point
     * there's not much we can do about that.
     */
    kill(cr.pid, SIGCONT);

    if (need_cleanup) {
        LOG("debuggerd committing suicide to free the zombie!\n");
        kill(getpid(), SIGKILL);
    }

    if(fd != -1) close(fd);
}


int main()
{
    int s;
    struct sigaction act;
    int logsocket = -1;

    /*
     * debuggerd crashes can't be reported to debuggerd.  Reset all of the
     * crash handlers.
     */
    signal(SIGILL, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGSTKFLT, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);

    logsocket = socket_local_client("logd",
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_DGRAM);
    if(logsocket < 0) {
        logsocket = -1;
    } else {
        fcntl(logsocket, F_SETFD, FD_CLOEXEC);
    }

    act.sa_handler = SIG_DFL;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask,SIGCHLD);
    act.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &act, 0);

    s = socket_local_server("android:debuggerd",
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if(s < 0) return -1;
    fcntl(s, F_SETFD, FD_CLOEXEC);

    LOG("debuggerd: " __DATE__ " " __TIME__ "\n");

    for(;;) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;

        alen = sizeof(addr);
        XLOG("waiting for connection\n");
        fd = accept(s, &addr, &alen);
        if(fd < 0) {
            XLOG("accept failed: %s\n", strerror(errno));
            continue;
        }

        fcntl(fd, F_SETFD, FD_CLOEXEC);

        handle_crashing_process(fd);
    }
    return 0;
}
