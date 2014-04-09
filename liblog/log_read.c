/*
** Copyright 2013-2014, The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#define NOMINMAX /* for windows to suppress definition of min in stdlib.h */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cutils/list.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <log/logger.h>

/* branchless on many architectures. */
#define min(x,y) ((y) ^ (((x) ^ (y)) & -((x) < (y))))

#define WEAK __attribute__((weak))
#define UNUSED __attribute__((unused))

/* Private copy of ../libcutils/socket_local_client.c prevent library loops */

#ifdef HAVE_WINSOCK

int WEAK socket_local_client(const char *name, int namespaceId, int type)
{
    errno = ENOSYS;
    return -ENOSYS;
}

#else /* !HAVE_WINSOCK */

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>

/* Private copy of ../libcutils/socket_local.h prevent library loops */
#define FILESYSTEM_SOCKET_PREFIX "/tmp/"
#define ANDROID_RESERVED_SOCKET_PREFIX "/dev/socket/"
/* End of ../libcutils/socket_local.h */

#define LISTEN_BACKLOG 4

/* Documented in header file. */
int WEAK socket_make_sockaddr_un(const char *name, int namespaceId,
                                 struct sockaddr_un *p_addr, socklen_t *alen)
{
    memset (p_addr, 0, sizeof (*p_addr));
    size_t namelen;

    switch (namespaceId) {
    case ANDROID_SOCKET_NAMESPACE_ABSTRACT:
#ifdef HAVE_LINUX_LOCAL_SOCKET_NAMESPACE
        namelen  = strlen(name);

        /* Test with length +1 for the *initial* '\0'. */
        if ((namelen + 1) > sizeof(p_addr->sun_path)) {
            goto error;
        }

        /*
         * Note: The path in this case is *not* supposed to be
         * '\0'-terminated. ("man 7 unix" for the gory details.)
         */

        p_addr->sun_path[0] = 0;
        memcpy(p_addr->sun_path + 1, name, namelen);
#else /*HAVE_LINUX_LOCAL_SOCKET_NAMESPACE*/
        /* this OS doesn't have the Linux abstract namespace */

        namelen = strlen(name) + strlen(FILESYSTEM_SOCKET_PREFIX);
        /* unix_path_max appears to be missing on linux */
        if (namelen > sizeof(*p_addr)
                - offsetof(struct sockaddr_un, sun_path) - 1) {
            goto error;
        }

        strcpy(p_addr->sun_path, FILESYSTEM_SOCKET_PREFIX);
        strcat(p_addr->sun_path, name);
#endif /*HAVE_LINUX_LOCAL_SOCKET_NAMESPACE*/
        break;

    case ANDROID_SOCKET_NAMESPACE_RESERVED:
        namelen = strlen(name) + strlen(ANDROID_RESERVED_SOCKET_PREFIX);
        /* unix_path_max appears to be missing on linux */
        if (namelen > sizeof(*p_addr)
                - offsetof(struct sockaddr_un, sun_path) - 1) {
            goto error;
        }

        strcpy(p_addr->sun_path, ANDROID_RESERVED_SOCKET_PREFIX);
        strcat(p_addr->sun_path, name);
        break;

    case ANDROID_SOCKET_NAMESPACE_FILESYSTEM:
        namelen = strlen(name);
        /* unix_path_max appears to be missing on linux */
        if (namelen > sizeof(*p_addr)
                - offsetof(struct sockaddr_un, sun_path) - 1) {
            goto error;
        }

        strcpy(p_addr->sun_path, name);
        break;

    default:
        /* invalid namespace id */
        return -1;
    }

    p_addr->sun_family = AF_LOCAL;
    *alen = namelen + offsetof(struct sockaddr_un, sun_path) + 1;
    return 0;
error:
    return -1;
}

/**
 * connect to peer named "name" on fd
 * returns same fd or -1 on error.
 * fd is not closed on error. that's your job.
 *
 * Used by AndroidSocketImpl
 */
int WEAK socket_local_client_connect(int fd, const char *name, int namespaceId,
                                     int type UNUSED)
{
    struct sockaddr_un addr;
    socklen_t alen;
    size_t namelen;
    int err;

    err = socket_make_sockaddr_un(name, namespaceId, &addr, &alen);

    if (err < 0) {
        goto error;
    }

    if(connect(fd, (struct sockaddr *) &addr, alen) < 0) {
        goto error;
    }

    return fd;

error:
    return -1;
}

/**
 * connect to peer named "name"
 * returns fd or -1 on error
 */
int WEAK socket_local_client(const char *name, int namespaceId, int type)
{
    int s;

    s = socket(AF_LOCAL, type, 0);
    if(s < 0) return -1;

    if ( 0 > socket_local_client_connect(s, name, namespaceId, type)) {
        close(s);
        return -1;
    }

    return s;
}

#endif /* !HAVE_WINSOCK */
/* End of ../libcutils/socket_local_client.c */

#define logger_for_each(logger, logger_list) \
    for (logger = node_to_item((logger_list)->node.next, struct logger, node); \
         logger != node_to_item(&(logger_list)->node, struct logger, node); \
         logger = node_to_item((logger)->node.next, struct logger, node))

/* In the future, we would like to make this list extensible */
static const char *LOG_NAME[LOG_ID_MAX] = {
    [LOG_ID_MAIN] = "main",
    [LOG_ID_RADIO] = "radio",
    [LOG_ID_EVENTS] = "events",
    [LOG_ID_SYSTEM] = "system"
};

const char *android_log_id_to_name(log_id_t log_id)
{
    if (log_id >= LOG_ID_MAX) {
        log_id = LOG_ID_MAIN;
    }
    return LOG_NAME[log_id];
}

log_id_t android_name_to_log_id(const char *logName)
{
    const char *b;
    int ret;

    if (!logName) {
        return -1; /* NB: log_id_t is unsigned */
    }
    b = strrchr(logName, '/');
    if (!b) {
        b = logName;
    } else {
        ++b;
    }

    for(ret = LOG_ID_MIN; ret < LOG_ID_MAX; ++ret) {
        const char *l = LOG_NAME[ret];
        if (l && !strcmp(b, l)) {
            return ret;
        }
    }
    return -1;   /* should never happen */
}

struct logger_list {
    struct listnode node;
    int mode;
    unsigned int tail;
    log_time start;
    pid_t pid;
    int sock;
};

struct logger {
    struct listnode node;
    struct logger_list *top;
    log_id_t id;
};

/* android_logger_alloc unimplemented, no use case */
/* android_logger_free not exported */
static void android_logger_free(struct logger *logger)
{
    if (!logger) {
        return;
    }

    list_remove(&logger->node);

    free(logger);
}

/* android_logger_alloc unimplemented, no use case */

/* method for getting the associated sublog id */
log_id_t android_logger_get_id(struct logger *logger)
{
    return logger->id;
}

/* worker for sending the command to the logger */
static ssize_t send_log_msg(struct logger *logger,
                            const char *msg, char *buf, size_t buf_size)
{
    ssize_t ret;
    int errno_save = 0;
    int sock = socket_local_client("logd", ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);
    if (sock < 0) {
        return sock;
    }

    if (msg) {
        snprintf(buf, buf_size, msg, logger ? logger->id : (unsigned) -1);
    }

    ret = write(sock, buf, strlen(buf) + 1);
    if (ret <= 0) {
        goto done;
    }

    ret = read(sock, buf, buf_size);

done:
    if ((ret == -1) && errno) {
        errno_save = errno;
    }
    close(sock);
    if (errno_save) {
        errno = errno_save;
    }
    return ret;
}

static int check_log_success(char *buf, ssize_t ret)
{
    if (ret < 0) {
        return ret;
    }

    if (strncmp(buf, "success", 7)) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int android_logger_clear(struct logger *logger)
{
    char buf[512];

    return check_log_success(buf,
        send_log_msg(logger, "clear %d", buf, sizeof(buf)));
}

/* returns the total size of the log's ring buffer */
long android_logger_get_log_size(struct logger *logger)
{
    char buf[512];

    ssize_t ret = send_log_msg(logger, "getLogSize %d", buf, sizeof(buf));
    if (ret < 0) {
        return ret;
    }

    if ((buf[0] < '0') || ('9' < buf[0])) {
        return -1;
    }

    return atol(buf);
}

int android_logger_set_log_size(struct logger *logger, unsigned long size)
{
    char buf[512];

    snprintf(buf, sizeof(buf), "setLogSize %d %lu",
        logger ? logger->id : (unsigned) -1, size);

    return check_log_success(buf, send_log_msg(NULL, NULL, buf, sizeof(buf)));
}

/*
 * returns the readable size of the log's ring buffer (that is, amount of the
 * log consumed)
 */
long android_logger_get_log_readable_size(struct logger *logger)
{
    char buf[512];

    ssize_t ret = send_log_msg(logger, "getLogSizeUsed %d", buf, sizeof(buf));
    if (ret < 0) {
        return ret;
    }

    if ((buf[0] < '0') || ('9' < buf[0])) {
        return -1;
    }

    return atol(buf);
}

/*
 * returns the logger version
 */
int android_logger_get_log_version(struct logger *logger UNUSED)
{
    return 3;
}

/*
 * returns statistics
 */
ssize_t android_logger_get_statistics(struct logger_list *logger_list,
                                      char *buf, size_t len)
{
    struct listnode *node;
    struct logger *logger;
    char *cp = buf;
    size_t remaining = len;
    size_t n;

    n = snprintf(cp, remaining, "getStatistics");
    n = min(n, remaining);
    remaining -= n;
    cp += n;

    logger_for_each(logger, logger_list) {
        n = snprintf(cp, remaining, " %d", logger->id);
        n = min(n, remaining);
        remaining -= n;
        cp += n;
    }
    return send_log_msg(NULL, NULL, buf, len);
}

ssize_t android_logger_get_prune_list(struct logger_list *logger_list UNUSED,
                                      char *buf, size_t len)
{
    return send_log_msg(NULL, "getPruneList", buf, len);
}

int android_logger_set_prune_list(struct logger_list *logger_list UNUSED,
                                  char *buf, size_t len)
{
    const char cmd[] = "setPruneList ";
    const size_t cmdlen = sizeof(cmd) - 1;

    if (strlen(buf) > (len - cmdlen)) {
        return -ENOMEM; /* KISS */
    }
    memmove(buf + cmdlen, buf, len - cmdlen);
    buf[len - 1] = '\0';
    memcpy(buf, cmd, cmdlen);

    return check_log_success(buf, send_log_msg(NULL, NULL, buf, len));
}

struct logger_list *android_logger_list_alloc(int mode,
                                              unsigned int tail,
                                              pid_t pid)
{
    struct logger_list *logger_list;

    logger_list = calloc(1, sizeof(*logger_list));
    if (!logger_list) {
        return NULL;
    }

    list_init(&logger_list->node);
    logger_list->mode = mode;
    logger_list->start.tv_sec = 0;
    logger_list->start.tv_nsec = 0;
    logger_list->tail = tail;
    logger_list->pid = pid;
    logger_list->sock = -1;

    return logger_list;
}

struct logger_list *android_logger_list_alloc_time(int mode,
                                                   log_time start,
                                                   pid_t pid)
{
    struct logger_list *logger_list;

    logger_list = calloc(1, sizeof(*logger_list));
    if (!logger_list) {
        return NULL;
    }

    list_init(&logger_list->node);
    logger_list->mode = mode;
    logger_list->start = start;
    logger_list->tail = 0;
    logger_list->pid = pid;
    logger_list->sock = -1;

    return logger_list;
}

/* android_logger_list_register unimplemented, no use case */
/* android_logger_list_unregister unimplemented, no use case */

/* Open the named log and add it to the logger list */
struct logger *android_logger_open(struct logger_list *logger_list,
                                   log_id_t id)
{
    struct listnode *node;
    struct logger *logger;
    char *n;

    if (!logger_list || (id >= LOG_ID_MAX)) {
        goto err;
    }

    logger_for_each(logger, logger_list) {
        if (logger->id == id) {
            goto ok;
        }
    }

    logger = calloc(1, sizeof(*logger));
    if (!logger) {
        goto err;
    }

    logger->id = id;
    list_add_tail(&logger_list->node, &logger->node);
    logger->top = logger_list;
    goto ok;

err:
    logger = NULL;
ok:
    return logger;
}

/* Open the single named log and make it part of a new logger list */
struct logger_list *android_logger_list_open(log_id_t id,
                                             int mode,
                                             unsigned int tail,
                                             pid_t pid)
{
    struct logger_list *logger_list = android_logger_list_alloc(mode, tail, pid);
    if (!logger_list) {
        return NULL;
    }

    if (!android_logger_open(logger_list, id)) {
        android_logger_list_free(logger_list);
        return NULL;
    }

    return logger_list;
}

static void caught_signal(int signum UNUSED)
{
}

/* Read from the selected logs */
int android_logger_list_read(struct logger_list *logger_list,
                             struct log_msg *log_msg)
{
    int ret, e;
    struct logger *logger;
    struct sigaction ignore;
    struct sigaction old_sigaction;
    unsigned int old_alarm = 0;

    if (!logger_list) {
        return -EINVAL;
    }

    if (logger_list->mode & O_NONBLOCK) {
        memset(&ignore, 0, sizeof(ignore));
        ignore.sa_handler = caught_signal;
        sigemptyset(&ignore.sa_mask);
    }

    if (logger_list->sock < 0) {
        char buffer[256], *cp, c;

        int sock = socket_local_client("logdr",
                                       ANDROID_SOCKET_NAMESPACE_RESERVED,
                                       SOCK_SEQPACKET);
        if (sock < 0) {
            if ((sock == -1) && errno) {
                return -errno;
            }
            return sock;
        }

        strcpy(buffer,
               (logger_list->mode & O_NONBLOCK) ? "dumpAndClose" : "stream");
        cp = buffer + strlen(buffer);

        strcpy(cp, " lids");
        cp += 5;
        c = '=';
        int remaining = sizeof(buffer) - (cp - buffer);
        logger_for_each(logger, logger_list) {
            ret = snprintf(cp, remaining, "%c%u", c, logger->id);
            ret = min(ret, remaining);
            remaining -= ret;
            cp += ret;
            c = ',';
        }

        if (logger_list->tail) {
            ret = snprintf(cp, remaining, " tail=%u", logger_list->tail);
            ret = min(ret, remaining);
            remaining -= ret;
            cp += ret;
        }

        if (logger_list->start.tv_sec || logger_list->start.tv_nsec) {
            ret = snprintf(cp, remaining, " start=%" PRIu32 ".%09" PRIu32,
                           logger_list->start.tv_sec,
                           logger_list->start.tv_nsec);
            ret = min(ret, remaining);
            remaining -= ret;
            cp += ret;
        }

        if (logger_list->pid) {
            ret = snprintf(cp, remaining, " pid=%u", logger_list->pid);
            ret = min(ret, remaining);
            remaining -= ret;
            cp += ret;
        }

        if (logger_list->mode & O_NONBLOCK) {
            /* Deal with an unresponsive logd */
            sigaction(SIGALRM, &ignore, &old_sigaction);
            old_alarm = alarm(30);
        }
        ret = write(sock, buffer, cp - buffer);
        e = errno;
        if (logger_list->mode & O_NONBLOCK) {
            if (e == EINTR) {
                e = ETIMEDOUT;
            }
            alarm(old_alarm);
            sigaction(SIGALRM, &old_sigaction, NULL);
        }

        if (ret <= 0) {
            close(sock);
            if ((ret == -1) && e) {
                return -e;
            }
            if (ret == 0) {
                return -EIO;
            }
            return ret;
        }

        logger_list->sock = sock;
    }

    ret = 0;
    while(1) {
        memset(log_msg, 0, sizeof(*log_msg));

        if (logger_list->mode & O_NONBLOCK) {
            /* particularily useful if tombstone is reporting for logd */
            sigaction(SIGALRM, &ignore, &old_sigaction);
            old_alarm = alarm(30);
        }
        /* NOTE: SOCK_SEQPACKET guarantees we read exactly one full entry */
        ret = recv(logger_list->sock, log_msg, LOGGER_ENTRY_MAX_LEN, 0);
        e = errno;
        if (logger_list->mode & O_NONBLOCK) {
            if ((ret == 0) || (e == EINTR)) {
                e = EAGAIN;
                ret = -1;
            }
            alarm(old_alarm);
            sigaction(SIGALRM, &old_sigaction, NULL);
        }

        if (ret <= 0) {
            if ((ret == -1) && e) {
                return -e;
            }
            return ret;
        }

        logger_for_each(logger, logger_list) {
            if (log_msg->entry.lid == logger->id) {
                return ret;
            }
        }
    }
    /* NOTREACH */
    return ret;
}

/* Close all the logs */
void android_logger_list_free(struct logger_list *logger_list)
{
    if (logger_list == NULL) {
        return;
    }

    while (!list_empty(&logger_list->node)) {
        struct listnode *node = list_head(&logger_list->node);
        struct logger *logger = node_to_item(node, struct logger, node);
        android_logger_free(logger);
    }

    if (logger_list->sock >= 0) {
        close (logger_list->sock);
    }

    free(logger_list);
}
