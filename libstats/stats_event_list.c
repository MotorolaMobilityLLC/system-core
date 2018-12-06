/*
 * Copyright (C) 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "include/stats_event_list.h"

#include <string.h>
#include <sys/time.h>
#include "statsd_writer.h"

#define MAX_EVENT_PAYLOAD (LOGGER_ENTRY_MAX_PAYLOAD - sizeof(int32_t))

typedef struct {
    uint32_t tag;
    unsigned pos;                                    /* Read/write position into buffer */
    unsigned count[ANDROID_MAX_LIST_NEST_DEPTH + 1]; /* Number of elements   */
    unsigned list[ANDROID_MAX_LIST_NEST_DEPTH + 1];  /* pos for list counter */
    unsigned list_nest_depth;
    unsigned len; /* Length or raw buffer. */
    bool overflow;
    bool list_stop; /* next call decrement list_nest_depth and issue a stop */
    enum {
        kAndroidLoggerRead = 1,
        kAndroidLoggerWrite = 2,
    } read_write_flag;
    uint8_t storage[LOGGER_ENTRY_MAX_PAYLOAD];
} android_log_context_internal;

extern struct android_log_transport_write statsdLoggerWrite;

static int __write_to_statsd_init(struct iovec* vec, size_t nr);
static int (*write_to_statsd)(struct iovec* vec, size_t nr) = __write_to_statsd_init;

// Similar to create_android_logger(), but instead of allocation a new buffer,
// this function resets the buffer for resuse.
void reset_log_context(android_log_context ctx) {
    if (!ctx) {
        return;
    }
    android_log_context_internal* context = (android_log_context_internal*)(ctx);
    uint32_t tag = context->tag;
    memset(context, 0, sizeof(android_log_context_internal));

    context->tag = tag;
    context->read_write_flag = kAndroidLoggerWrite;
    size_t needed = sizeof(uint8_t) + sizeof(uint8_t);
    if ((context->pos + needed) > MAX_EVENT_PAYLOAD) {
        context->overflow = true;
    }
    /* Everything is a list */
    context->storage[context->pos + 0] = EVENT_TYPE_LIST;
    context->list[0] = context->pos + 1;
    context->pos += needed;
}

int stats_write_list(android_log_context ctx) {
    android_log_context_internal* context;
    const char* msg;
    ssize_t len;

    context = (android_log_context_internal*)(ctx);
    if (!context || (kAndroidLoggerWrite != context->read_write_flag)) {
        return -EBADF;
    }

    if (context->list_nest_depth) {
        return -EIO;
    }

    /* NB: if there was overflow, then log is truncated. Nothing reported */
    context->storage[1] = context->count[0];
    len = context->len = context->pos;
    msg = (const char*)context->storage;
    /* it's not a list */
    if (context->count[0] <= 1) {
        len -= sizeof(uint8_t) + sizeof(uint8_t);
        if (len < 0) {
            len = 0;
        }
        msg += sizeof(uint8_t) + sizeof(uint8_t);
    }

    struct iovec vec[2];
    vec[0].iov_base = &context->tag;
    vec[0].iov_len = sizeof(context->tag);
    vec[1].iov_base = (void*)msg;
    vec[1].iov_len = len;
    return write_to_statsd(vec, 2);
}

int write_to_logger(android_log_context ctx, log_id_t id) {
    int retValue = 0;

    if (WRITE_TO_LOGD) {
        retValue = android_log_write_list(ctx, id);
    }

    if (WRITE_TO_STATSD) {
        // log_event_list's cast operator is overloaded.
        int ret = stats_write_list(ctx);
        // In debugging phase, we may write to both logd and statsd. Prefer to
        // return statsd socket write error code here.
        if (ret < 0) {
            retValue = ret;
        }
    }

    return retValue;
}

void note_log_drop() {
    statsdLoggerWrite.noteDrop();
}

void stats_log_close() {
    statsd_writer_init_lock();
    write_to_statsd = __write_to_statsd_init;
    if (statsdLoggerWrite.close) {
        (*statsdLoggerWrite.close)();
    }
    statsd_writer_init_unlock();
}

/* log_init_lock assumed */
static int __write_to_statsd_initialize_locked() {
    if (!statsdLoggerWrite.open || ((*statsdLoggerWrite.open)() < 0)) {
        if (statsdLoggerWrite.close) {
            (*statsdLoggerWrite.close)();
            return -ENODEV;
        }
    }
    return 1;
}

static int __write_to_stats_daemon(struct iovec* vec, size_t nr) {
    int save_errno;
    struct timespec ts;
    size_t len, i;

    for (len = i = 0; i < nr; ++i) {
        len += vec[i].iov_len;
    }
    if (!len) {
        return -EINVAL;
    }

    save_errno = errno;
#if defined(__ANDROID__)
    clock_gettime(CLOCK_REALTIME, &ts);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts.tv_sec = tv.tv_sec;
    ts.tv_nsec = tv.tv_usec * 1000;
#endif

    int ret = (int)(*statsdLoggerWrite.write)(&ts, vec, nr);
    errno = save_errno;
    return ret;
}

static int __write_to_statsd_init(struct iovec* vec, size_t nr) {
    int ret, save_errno = errno;

    statsd_writer_init_lock();

    if (write_to_statsd == __write_to_statsd_init) {
        ret = __write_to_statsd_initialize_locked();
        if (ret < 0) {
            statsd_writer_init_unlock();
            errno = save_errno;
            return ret;
        }

        write_to_statsd = __write_to_stats_daemon;
    }

    statsd_writer_init_unlock();

    ret = write_to_statsd(vec, nr);
    errno = save_errno;
    return ret;
}

static inline void copy4LE(uint8_t* buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

// Note: this function differs from android_log_write_string8_len in that the length passed in
// should be treated as actual length and not max length.
int android_log_write_char_array(android_log_context ctx, const char* value, size_t actual_len) {
    size_t needed;
    ssize_t len = actual_len;
    android_log_context_internal* context;

    context = (android_log_context_internal*)ctx;
    if (!context || (kAndroidLoggerWrite != context->read_write_flag)) {
        return -EBADF;
    }
    if (context->overflow) {
        return -EIO;
    }
    if (!value) {
        value = "";
        len = 0;
    }
    needed = sizeof(uint8_t) + sizeof(int32_t) + len;
    if ((context->pos + needed) > MAX_EVENT_PAYLOAD) {
        /* Truncate string for delivery */
        len = MAX_EVENT_PAYLOAD - context->pos - 1 - sizeof(int32_t);
        if (len <= 0) {
            context->overflow = true;
            return -EIO;
        }
    }
    context->count[context->list_nest_depth]++;
    context->storage[context->pos + 0] = EVENT_TYPE_STRING;
    copy4LE(&context->storage[context->pos + 1], len);
    if (len) {
        memcpy(&context->storage[context->pos + 5], value, len);
    }
    context->pos += needed;
    return len;
}
