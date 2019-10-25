/*
 * Copyright (C) 2007-2016 The Android Open Source Project
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
#include <inttypes.h>
#include <poll.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "log_portability.h"
#include "logger.h"
#include "uio.h"

static int logdAvailable(log_id_t LogId);
static int logdOpen();
static void logdClose();
static int logdWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr);

struct android_log_transport_write logdLoggerWrite = {
    .name = "logd",
    .logMask = 0,
    .context.sock = -EBADF,
    .available = logdAvailable,
    .open = logdOpen,
    .close = logdClose,
    .write = logdWrite,
};

/* log_init_lock assumed */
static int logdOpen() {
  int i, ret = 0;

  i = atomic_load(&logdLoggerWrite.context.sock);
  if (i < 0) {
    int sock = TEMP_FAILURE_RETRY(socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (sock < 0) {
      ret = -errno;
    } else {
      struct sockaddr_un un;
      memset(&un, 0, sizeof(struct sockaddr_un));
      un.sun_family = AF_UNIX;
      strcpy(un.sun_path, "/dev/socket/logdw");

      if (TEMP_FAILURE_RETRY(connect(sock, (struct sockaddr*)&un, sizeof(struct sockaddr_un))) <
          0) {
        ret = -errno;
        switch (ret) {
          case -ENOTCONN:
          case -ECONNREFUSED:
          case -ENOENT:
            i = atomic_exchange(&logdLoggerWrite.context.sock, ret);
            [[fallthrough]];
          default:
            break;
        }
        close(sock);
      } else {
        ret = atomic_exchange(&logdLoggerWrite.context.sock, sock);
        if ((ret >= 0) && (ret != sock)) {
          close(ret);
        }
        ret = 0;
      }
    }
  }

  return ret;
}

static void __logdClose(int negative_errno) {
  int sock = atomic_exchange(&logdLoggerWrite.context.sock, negative_errno);
  if (sock >= 0) {
    close(sock);
  }
}

static void logdClose() {
  __logdClose(-EBADF);
}

static int logdAvailable(log_id_t logId) {
  if (logId >= LOG_ID_MAX || logId == LOG_ID_KERNEL) {
    return -EINVAL;
  }
  if (atomic_load(&logdLoggerWrite.context.sock) < 0) {
    if (access("/dev/socket/logdw", W_OK) == 0) {
      return 0;
    }
    return -EBADF;
  }
  return 1;
}

static int logdWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr) {
  ssize_t ret;
  int sock;
  static const unsigned headerLength = 1;
  struct iovec newVec[nr + headerLength];
  android_log_header_t header;
  size_t i, payloadSize;
  static atomic_int dropped;
  static atomic_int droppedSecurity;

  sock = atomic_load(&logdLoggerWrite.context.sock);
  if (sock < 0) switch (sock) {
      case -ENOTCONN:
      case -ECONNREFUSED:
      case -ENOENT:
        break;
      default:
        return -EBADF;
    }

  /* logd, after initialization and priv drop */
  if (__android_log_uid() == AID_LOGD) {
    /*
     * ignore log messages we send to ourself (logd).
     * Such log messages are often generated by libraries we depend on
     * which use standard Android logging.
     */
    return 0;
  }

  header.tid = gettid();
  header.realtime.tv_sec = ts->tv_sec;
  header.realtime.tv_nsec = ts->tv_nsec;

  newVec[0].iov_base = (unsigned char*)&header;
  newVec[0].iov_len = sizeof(header);

  if (sock >= 0) {
    int32_t snapshot = atomic_exchange_explicit(&droppedSecurity, 0, memory_order_relaxed);
    if (snapshot) {
      android_log_event_int_t buffer;

      header.id = LOG_ID_SECURITY;
      buffer.header.tag = LIBLOG_LOG_TAG;
      buffer.payload.type = EVENT_TYPE_INT;
      buffer.payload.data = snapshot;

      newVec[headerLength].iov_base = &buffer;
      newVec[headerLength].iov_len = sizeof(buffer);

      ret = TEMP_FAILURE_RETRY(writev(sock, newVec, 2));
      if (ret != (ssize_t)(sizeof(header) + sizeof(buffer))) {
        atomic_fetch_add_explicit(&droppedSecurity, snapshot, memory_order_relaxed);
      }
    }
    snapshot = atomic_exchange_explicit(&dropped, 0, memory_order_relaxed);
    if (snapshot && __android_log_is_loggable_len(ANDROID_LOG_INFO, "liblog", strlen("liblog"),
                                                  ANDROID_LOG_VERBOSE)) {
      android_log_event_int_t buffer;

      header.id = LOG_ID_EVENTS;
      buffer.header.tag = LIBLOG_LOG_TAG;
      buffer.payload.type = EVENT_TYPE_INT;
      buffer.payload.data = snapshot;

      newVec[headerLength].iov_base = &buffer;
      newVec[headerLength].iov_len = sizeof(buffer);

      ret = TEMP_FAILURE_RETRY(writev(sock, newVec, 2));
      if (ret != (ssize_t)(sizeof(header) + sizeof(buffer))) {
        atomic_fetch_add_explicit(&dropped, snapshot, memory_order_relaxed);
      }
    }
  }

  header.id = logId;

  for (payloadSize = 0, i = headerLength; i < nr + headerLength; i++) {
    newVec[i].iov_base = vec[i - headerLength].iov_base;
    payloadSize += newVec[i].iov_len = vec[i - headerLength].iov_len;

    if (payloadSize > LOGGER_ENTRY_MAX_PAYLOAD) {
      newVec[i].iov_len -= payloadSize - LOGGER_ENTRY_MAX_PAYLOAD;
      if (newVec[i].iov_len) {
        ++i;
      }
      break;
    }
  }

  /*
   * The write below could be lost, but will never block.
   *
   * ENOTCONN occurs if logd has died.
   * ENOENT occurs if logd is not running and socket is missing.
   * ECONNREFUSED occurs if we can not reconnect to logd.
   * EAGAIN occurs if logd is overloaded.
   */
  if (sock < 0) {
    ret = sock;
  } else {
    ret = TEMP_FAILURE_RETRY(writev(sock, newVec, i));
    if (ret < 0) {
      ret = -errno;
    }
  }
  switch (ret) {
    case -ENOTCONN:
    case -ECONNREFUSED:
    case -ENOENT:
      if (__android_log_trylock()) {
        return ret; /* in a signal handler? try again when less stressed */
      }
      __logdClose(ret);
      ret = logdOpen();
      __android_log_unlock();

      if (ret < 0) {
        return ret;
      }

      ret = TEMP_FAILURE_RETRY(writev(atomic_load(&logdLoggerWrite.context.sock), newVec, i));
      if (ret < 0) {
        ret = -errno;
      }
      [[fallthrough]];
    default:
      break;
  }

  if (ret > (ssize_t)sizeof(header)) {
    ret -= sizeof(header);
  } else if (ret == -EAGAIN) {
    atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
    if (logId == LOG_ID_SECURITY) {
      atomic_fetch_add_explicit(&droppedSecurity, 1, memory_order_relaxed);
    }
  }

  return ret;
}
