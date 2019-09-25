/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cutils/klog.h>
#include <log/log.h>
#include <logwrap/logwrap.h>

#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(*(x)))
#define MIN(a,b) (((a)<(b))?(a):(b))

static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;
// Protected by fd_mutex.  These signals must be blocked while modifying as well.
static pid_t child_pid;
static struct sigaction old_int;
static struct sigaction old_quit;
static struct sigaction old_hup;

#define ERROR(fmt, args...)                                                   \
do {                                                                          \
    fprintf(stderr, fmt, ## args);                                            \
    ALOG(LOG_ERROR, "logwrapper", fmt, ## args);                              \
} while(0)

#define FATAL_CHILD(fmt, args...)                                             \
do {                                                                          \
    ERROR(fmt, ## args);                                                      \
    _exit(-1);                                                                \
} while(0)

#define MAX_KLOG_TAG 16

/* This is a simple buffer that holds up to the first beginning_buf->buf_size
 * bytes of output from a command.
 */
#define BEGINNING_BUF_SIZE 0x1000
struct beginning_buf {
    char *buf;
    size_t alloc_len;
    /* buf_size is the usable space, which is one less than the allocated size */
    size_t buf_size;
    size_t used_len;
};

/* This is a circular buf that holds up to the last ending_buf->buf_size bytes
 * of output from a command after the first beginning_buf->buf_size bytes
 * (which are held in beginning_buf above).
 */
#define ENDING_BUF_SIZE 0x1000
struct ending_buf {
    char *buf;
    ssize_t alloc_len;
    /* buf_size is the usable space, which is one less than the allocated size */
    ssize_t buf_size;
    ssize_t used_len;
    /* read and write offsets into the circular buffer */
    int read;
    int write;
};

 /* A structure to hold all the abbreviated buf data */
struct abbr_buf {
    struct beginning_buf b_buf;
    struct ending_buf e_buf;
    int beginning_buf_full;
};

/* Collect all the various bits of info needed for logging in one place. */
struct log_info {
    int log_target;
    char klog_fmt[MAX_KLOG_TAG * 2];
    char *btag;
    bool abbreviated;
    FILE *fp;
    struct abbr_buf a_buf;
};

/* Forware declaration */
static void add_line_to_abbr_buf(struct abbr_buf *a_buf, char *linebuf, int linelen);

/* Return 0 on success, and 1 when full */
static int add_line_to_linear_buf(struct beginning_buf *b_buf,
                                   char *line, ssize_t line_len)
{
    int full = 0;

    if ((line_len + b_buf->used_len) > b_buf->buf_size) {
        full = 1;
    } else {
        /* Add to the end of the buf */
        memcpy(b_buf->buf + b_buf->used_len, line, line_len);
        b_buf->used_len += line_len;
    }

    return full;
}

static void add_line_to_circular_buf(struct ending_buf *e_buf,
                                     char *line, ssize_t line_len)
{
    ssize_t free_len;
    ssize_t needed_space;
    int cnt;

    if (e_buf->buf == NULL) {
        return;
    }

   if (line_len > e_buf->buf_size) {
       return;
   }

    free_len = e_buf->buf_size - e_buf->used_len;

    if (line_len > free_len) {
        /* remove oldest entries at read, and move read to make
         * room for the new string */
        needed_space = line_len - free_len;
        e_buf->read = (e_buf->read + needed_space) % e_buf->buf_size;
        e_buf->used_len -= needed_space;
    }

    /* Copy the line into the circular buffer, dealing with possible
     * wraparound.
     */
    cnt = MIN(line_len, e_buf->buf_size - e_buf->write);
    memcpy(e_buf->buf + e_buf->write, line, cnt);
    if (cnt < line_len) {
        memcpy(e_buf->buf, line + cnt, line_len - cnt);
    }
    e_buf->used_len += line_len;
    e_buf->write = (e_buf->write + line_len) % e_buf->buf_size;
}

/* Log directly to the specified log */
static void do_log_line(struct log_info *log_info, char *line) {
    if (log_info->log_target & LOG_KLOG) {
        klog_write(6, log_info->klog_fmt, line);
    }
    if (log_info->log_target & LOG_ALOG) {
        ALOG(LOG_INFO, log_info->btag, "%s", line);
    }
    if (log_info->log_target & LOG_FILE) {
        fprintf(log_info->fp, "%s\n", line);
    }
}

/* Log to either the abbreviated buf, or directly to the specified log
 * via do_log_line() above.
 */
static void log_line(struct log_info *log_info, char *line, int len) {
    if (log_info->abbreviated) {
        add_line_to_abbr_buf(&log_info->a_buf, line, len);
    } else {
        do_log_line(log_info, line);
    }
}

/*
 * The kernel will take a maximum of 1024 bytes in any single write to
 * the kernel logging device file, so find and print each line one at
 * a time.  The allocated size for buf should be at least 1 byte larger
 * than buf_size (the usable size of the buffer) to make sure there is
 * room to temporarily stuff a null byte to terminate a line for logging.
 */
static void print_buf_lines(struct log_info *log_info, char *buf, int buf_size)
{
    char *line_start;
    char c;
    int i;

    line_start = buf;
    for (i = 0; i < buf_size; i++) {
        if (*(buf + i) == '\n') {
            /* Found a line ending, print the line and compute new line_start */
            /* Save the next char and replace with \0 */
            c = *(buf + i + 1);
            *(buf + i + 1) = '\0';
            do_log_line(log_info, line_start);
            /* Restore the saved char */
            *(buf + i + 1) = c;
            line_start = buf + i + 1;
        } else if (*(buf + i) == '\0') {
            /* The end of the buffer, print the last bit */
            do_log_line(log_info, line_start);
            break;
        }
    }
    /* If the buffer was completely full, and didn't end with a newline, just
     * ignore the partial last line.
     */
}

static void init_abbr_buf(struct abbr_buf *a_buf) {
    char *new_buf;

    memset(a_buf, 0, sizeof(struct abbr_buf));
    new_buf = malloc(BEGINNING_BUF_SIZE);
    if (new_buf) {
        a_buf->b_buf.buf = new_buf;
        a_buf->b_buf.alloc_len = BEGINNING_BUF_SIZE;
        a_buf->b_buf.buf_size = BEGINNING_BUF_SIZE - 1;
    }
    new_buf = malloc(ENDING_BUF_SIZE);
    if (new_buf) {
        a_buf->e_buf.buf = new_buf;
        a_buf->e_buf.alloc_len = ENDING_BUF_SIZE;
        a_buf->e_buf.buf_size = ENDING_BUF_SIZE - 1;
    }
}

static void free_abbr_buf(struct abbr_buf *a_buf) {
    free(a_buf->b_buf.buf);
    free(a_buf->e_buf.buf);
}

static void add_line_to_abbr_buf(struct abbr_buf *a_buf, char *linebuf, int linelen) {
    if (!a_buf->beginning_buf_full) {
        a_buf->beginning_buf_full =
            add_line_to_linear_buf(&a_buf->b_buf, linebuf, linelen);
    }
    if (a_buf->beginning_buf_full) {
        add_line_to_circular_buf(&a_buf->e_buf, linebuf, linelen);
    }
}

static void print_abbr_buf(struct log_info *log_info) {
    struct abbr_buf *a_buf = &log_info->a_buf;

    /* Add the abbreviated output to the kernel log */
    if (a_buf->b_buf.alloc_len) {
        print_buf_lines(log_info, a_buf->b_buf.buf, a_buf->b_buf.used_len);
    }

    /* Print an ellipsis to indicate that the buffer has wrapped or
     * is full, and some data was not logged.
     */
    if (a_buf->e_buf.used_len == a_buf->e_buf.buf_size) {
        do_log_line(log_info, "...\n");
    }

    if (a_buf->e_buf.used_len == 0) {
        return;
    }

    /* Simplest way to print the circular buffer is allocate a second buf
     * of the same size, and memcpy it so it's a simple linear buffer,
     * and then cal print_buf_lines on it */
    if (a_buf->e_buf.read < a_buf->e_buf.write) {
        /* no wrap around, just print it */
        print_buf_lines(log_info, a_buf->e_buf.buf + a_buf->e_buf.read,
                        a_buf->e_buf.used_len);
    } else {
        /* The circular buffer will always have at least 1 byte unused,
         * so by allocating alloc_len here we will have at least
         * 1 byte of space available as required by print_buf_lines().
         */
        char * nbuf = malloc(a_buf->e_buf.alloc_len);
        if (!nbuf) {
            return;
        }
        int first_chunk_len = a_buf->e_buf.buf_size - a_buf->e_buf.read;
        memcpy(nbuf, a_buf->e_buf.buf + a_buf->e_buf.read, first_chunk_len);
        /* copy second chunk */
        memcpy(nbuf + first_chunk_len, a_buf->e_buf.buf, a_buf->e_buf.write);
        print_buf_lines(log_info, nbuf, first_chunk_len + a_buf->e_buf.write);
        free(nbuf);
    }
}

static void signal_handler(int signal_num);

static void block_signals(sigset_t* oldset) {
    sigset_t blockset;

    sigemptyset(&blockset);
    sigaddset(&blockset, SIGINT);
    sigaddset(&blockset, SIGQUIT);
    sigaddset(&blockset, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &blockset, oldset);
}

static void unblock_signals(sigset_t* oldset) {
    pthread_sigmask(SIG_SETMASK, oldset, NULL);
}

static void setup_signal_handlers(pid_t pid) {
    struct sigaction handler = {.sa_handler = signal_handler};

    child_pid = pid;
    sigaction(SIGINT, &handler, &old_int);
    sigaction(SIGQUIT, &handler, &old_quit);
    sigaction(SIGHUP, &handler, &old_hup);
}

static void restore_signal_handlers() {
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGQUIT, &old_quit, NULL);
    sigaction(SIGHUP, &old_hup, NULL);
    child_pid = 0;
}

static void signal_handler(int signal_num) {
    if (child_pid == 0 || kill(child_pid, signal_num) != 0) {
        restore_signal_handlers();
        raise(signal_num);
    }
}

static int parent(const char* tag, int parent_read, pid_t pid, int* chld_sts, int log_target,
                  bool abbreviated, char* file_path, bool forward_signals) {
    int status = 0;
    char buffer[4096];
    struct pollfd poll_fds[] = {
        [0] = {
            .fd = parent_read,
            .events = POLLIN,
        },
    };
    int rc = 0;
    int fd;

    struct log_info log_info;

    int a = 0;  // start index of unprocessed data
    int b = 0;  // end index of unprocessed data
    int sz;
    bool found_child = false;
    // There is a very small chance that opening child_ptty in the child will fail, but in this case
    // POLLHUP will not be generated below.  Therefore, we use a 1 second timeout for poll() until
    // we receive a message from child_ptty.  If this times out, we call waitpid() with WNOHANG to
    // check the status of the child process and exit appropriately if it has terminated.
    bool received_messages = false;
    char tmpbuf[256];

    log_info.btag = basename(tag);
    if (!log_info.btag) {
        log_info.btag = (char*) tag;
    }

    if (abbreviated && (log_target == LOG_NONE)) {
        abbreviated = 0;
    }
    if (abbreviated) {
        init_abbr_buf(&log_info.a_buf);
    }

    if (log_target & LOG_KLOG) {
        snprintf(log_info.klog_fmt, sizeof(log_info.klog_fmt),
                 "<6>%.*s: %%s\n", MAX_KLOG_TAG, log_info.btag);
    }

    if ((log_target & LOG_FILE) && !file_path) {
        /* No file_path specified, clear the LOG_FILE bit */
        log_target &= ~LOG_FILE;
    }

    if (log_target & LOG_FILE) {
        fd = open(file_path, O_WRONLY | O_CREAT, 0664);
        if (fd < 0) {
            ERROR("Cannot log to file %s\n", file_path);
            log_target &= ~LOG_FILE;
        } else {
            lseek(fd, 0, SEEK_END);
            log_info.fp = fdopen(fd, "a");
        }
    }

    log_info.log_target = log_target;
    log_info.abbreviated = abbreviated;

    while (!found_child) {
        int timeout = received_messages ? -1 : 1000;
        if (TEMP_FAILURE_RETRY(poll(poll_fds, ARRAY_SIZE(poll_fds), timeout)) < 0) {
            ERROR("poll failed\n");
            rc = -1;
            goto err_poll;
        }

        if (poll_fds[0].revents & POLLIN) {
            received_messages = true;
            sz = TEMP_FAILURE_RETRY(
                read(parent_read, &buffer[b], sizeof(buffer) - 1 - b));

            sz += b;
            // Log one line at a time
            for (b = 0; b < sz; b++) {
                if (buffer[b] == '\r') {
                    if (abbreviated) {
                        /* The abbreviated logging code uses newline as
                         * the line separator.  Lucikly, the pty layer
                         * helpfully cooks the output of the command
                         * being run and inserts a CR before NL.  So
                         * I just change it to NL here when doing
                         * abbreviated logging.
                         */
                        buffer[b] = '\n';
                    } else {
                        buffer[b] = '\0';
                    }
                } else if (buffer[b] == '\n') {
                    buffer[b] = '\0';
                    log_line(&log_info, &buffer[a], b - a);
                    a = b + 1;
                }
            }

            if (a == 0 && b == sizeof(buffer) - 1) {
                // buffer is full, flush
                buffer[b] = '\0';
                log_line(&log_info, &buffer[a], b - a);
                b = 0;
            } else if (a != b) {
                // Keep left-overs
                b -= a;
                memmove(buffer, &buffer[a], b);
                a = 0;
            } else {
                a = 0;
                b = 0;
            }
        }

        if (!received_messages || (poll_fds[0].revents & POLLHUP)) {
            int ret;
            sigset_t oldset;

            if (forward_signals) {
                // Our signal handlers forward these signals to 'child_pid', but waitpid() may reap
                // the child, so we must block these signals until we either 1) conclude that the
                // child is still running or 2) determine the child has been reaped and we have
                // reset the signals to their original disposition.
                block_signals(&oldset);
            }

            int flags = (poll_fds[0].revents & POLLHUP) ? 0 : WNOHANG;
            ret = TEMP_FAILURE_RETRY(waitpid(pid, &status, flags));
            if (ret < 0) {
                rc = errno;
                ALOG(LOG_ERROR, "logwrap", "waitpid failed with %s\n", strerror(errno));
                goto err_waitpid;
            }
            if (ret > 0) {
                found_child = true;
            }

            if (forward_signals) {
                if (found_child) {
                    restore_signal_handlers();
                }
                unblock_signals(&oldset);
            }
        }
    }

    if (chld_sts != NULL) {
        *chld_sts = status;
    } else {
      if (WIFEXITED(status))
        rc = WEXITSTATUS(status);
      else
        rc = -ECHILD;
    }

    // Flush remaining data
    if (a != b) {
      buffer[b] = '\0';
      log_line(&log_info, &buffer[a], b - a);
    }

    /* All the output has been processed, time to dump the abbreviated output */
    if (abbreviated) {
        print_abbr_buf(&log_info);
    }

    if (WIFEXITED(status)) {
      if (WEXITSTATUS(status)) {
        snprintf(tmpbuf, sizeof(tmpbuf),
                 "%s terminated by exit(%d)\n", log_info.btag, WEXITSTATUS(status));
        do_log_line(&log_info, tmpbuf);
      }
    } else {
      if (WIFSIGNALED(status)) {
        snprintf(tmpbuf, sizeof(tmpbuf),
                       "%s terminated by signal %d\n", log_info.btag, WTERMSIG(status));
        do_log_line(&log_info, tmpbuf);
      } else if (WIFSTOPPED(status)) {
        snprintf(tmpbuf, sizeof(tmpbuf),
                       "%s stopped by signal %d\n", log_info.btag, WSTOPSIG(status));
        do_log_line(&log_info, tmpbuf);
      }
    }

err_waitpid:
err_poll:
    if (log_target & LOG_FILE) {
        fclose(log_info.fp); /* Also closes underlying fd */
    }
    if (abbreviated) {
        free_abbr_buf(&log_info.a_buf);
    }
    return rc;
}

static void child(int argc, char* argv[]) {
    // create null terminated argv_child array
    char* argv_child[argc + 1];
    memcpy(argv_child, argv, argc * sizeof(char *));
    argv_child[argc] = NULL;

    if (execvp(argv_child[0], argv_child)) {
        FATAL_CHILD("executing %s failed: %s\n", argv_child[0],
                strerror(errno));
    }
}

int android_fork_execvp_ext2(int argc, char* argv[], int* status, bool forward_signals,
                             int log_target, bool abbreviated, char* file_path) {
    pid_t pid;
    int parent_ptty;
    sigset_t blockset;
    sigset_t oldset;
    int rc = 0;

    rc = pthread_mutex_lock(&fd_mutex);
    if (rc) {
        ERROR("failed to lock signal_fd mutex\n");
        goto err_lock;
    }

    /* Use ptty instead of socketpair so that STDOUT is not buffered */
    parent_ptty = TEMP_FAILURE_RETRY(posix_openpt(O_RDWR | O_CLOEXEC));
    if (parent_ptty < 0) {
        ERROR("Cannot create parent ptty\n");
        rc = -1;
        goto err_open;
    }

    char child_devname[64];
    if (grantpt(parent_ptty) || unlockpt(parent_ptty) ||
            ptsname_r(parent_ptty, child_devname, sizeof(child_devname)) != 0) {
        ERROR("Problem with /dev/ptmx\n");
        rc = -1;
        goto err_ptty;
    }

    if (forward_signals) {
        // Block these signals until we have the child pid and our signal handlers set up.
        block_signals(&oldset);
    }

    pid = fork();
    if (pid < 0) {
        ERROR("Failed to fork\n");
        rc = -1;
        goto err_fork;
    } else if (pid == 0) {
        pthread_mutex_unlock(&fd_mutex);
        unblock_signals(&oldset);

        setsid();

        int child_ptty = TEMP_FAILURE_RETRY(open(child_devname, O_RDWR | O_CLOEXEC));
        if (child_ptty < 0) {
            FATAL_CHILD("Cannot open child_ptty: %s\n", strerror(errno));
        }
        close(parent_ptty);

        dup2(child_ptty, 1);
        dup2(child_ptty, 2);
        close(child_ptty);

        child(argc, argv);
    } else {
        if (forward_signals) {
            setup_signal_handlers(pid);
            unblock_signals(&oldset);
        }

        rc = parent(argv[0], parent_ptty, pid, status, log_target, abbreviated, file_path,
                    forward_signals);

        if (forward_signals) {
            restore_signal_handlers();
        }
    }

err_fork:
    if (forward_signals) {
        unblock_signals(&oldset);
    }
err_ptty:
    close(parent_ptty);
err_open:
    pthread_mutex_unlock(&fd_mutex);
err_lock:
    return rc;
}
