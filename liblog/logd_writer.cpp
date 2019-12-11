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

#include <shared_mutex>

#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "log_portability.h"
#include "logger.h"
#include "rwlock.h"
#include "uio.h"

static int LogdWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr);
static void LogdClose();

struct android_log_transport_write logdLoggerWrite = {
    .name = "logd",
    .logMask = 0,
    .available = [](log_id_t) { return 0; },
    .open = [] { return 0; },
    .close = LogdClose,
    .write = LogdWrite,
};

static int logd_socket;
static RwLock logd_socket_lock;

static void OpenSocketLocked() {
  logd_socket = TEMP_FAILURE_RETRY(socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  if (logd_socket <= 0) {
    return;
  }

  sockaddr_un un = {};
  un.sun_family = AF_UNIX;
  strcpy(un.sun_path, "/dev/socket/logdw");

  if (TEMP_FAILURE_RETRY(
          connect(logd_socket, reinterpret_cast<sockaddr*>(&un), sizeof(sockaddr_un))) < 0) {
    close(logd_socket);
    logd_socket = 0;
  }
}

static void OpenSocket() {
  auto lock = std::unique_lock{logd_socket_lock};
  if (logd_socket > 0) {
    // Someone raced us and opened the socket already.
    return;
  }

  OpenSocketLocked();
}

static void ResetSocket(int old_socket) {
  auto lock = std::unique_lock{logd_socket_lock};
  if (old_socket != logd_socket) {
    // Someone raced us and reset the socket already.
    return;
  }
  close(logd_socket);
  logd_socket = 0;
  OpenSocketLocked();
}

static void LogdClose() {
  auto lock = std::unique_lock{logd_socket_lock};
  if (logd_socket > 0) {
    close(logd_socket);
  }
  logd_socket = 0;
}

static int LogdWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr) {
  ssize_t ret;
  static const unsigned headerLength = 1;
  struct iovec newVec[nr + headerLength];
  android_log_header_t header;
  size_t i, payloadSize;
  static atomic_int dropped;
  static atomic_int droppedSecurity;

  auto lock = std::shared_lock{logd_socket_lock};
  if (logd_socket <= 0) {
    lock.unlock();
    OpenSocket();
    lock.lock();
  }

  if (logd_socket <= 0) {
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

  int32_t snapshot = atomic_exchange_explicit(&droppedSecurity, 0, memory_order_relaxed);
  if (snapshot) {
    android_log_event_int_t buffer;

    header.id = LOG_ID_SECURITY;
    buffer.header.tag = LIBLOG_LOG_TAG;
    buffer.payload.type = EVENT_TYPE_INT;
    buffer.payload.data = snapshot;

    newVec[headerLength].iov_base = &buffer;
    newVec[headerLength].iov_len = sizeof(buffer);

    ret = TEMP_FAILURE_RETRY(writev(logd_socket, newVec, 2));
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

    ret = TEMP_FAILURE_RETRY(writev(logd_socket, newVec, 2));
    if (ret != (ssize_t)(sizeof(header) + sizeof(buffer))) {
      atomic_fetch_add_explicit(&dropped, snapshot, memory_order_relaxed);
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

  // The write below could be lost, but will never block.
  // EAGAIN occurs if logd is overloaded, other errors indicate that something went wrong with
  // the connection, so we reset it and try again.
  ret = TEMP_FAILURE_RETRY(writev(logd_socket, newVec, i));
  if (ret < 0 && errno != EAGAIN) {
    int old_socket = logd_socket;
    lock.unlock();
    ResetSocket(old_socket);
    lock.lock();

    ret = TEMP_FAILURE_RETRY(writev(logd_socket, newVec, i));
  }

  if (ret < 0) {
    ret = -errno;
  }

  if (ret > (ssize_t)sizeof(header)) {
    ret -= sizeof(header);
  } else if (ret < 0) {
    atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
    if (logId == LOG_ID_SECURITY) {
      atomic_fetch_add_explicit(&droppedSecurity, 1, memory_order_relaxed);
    }
  }

  return ret;
}
