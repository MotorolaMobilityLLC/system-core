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

#include "logd_writer.h"

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

#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "logger.h"
#include "rwlock.h"
#include "uio.h"

#if defined(MTK_LOGD_ENHANCE) && defined(ANDROID_LOG_MUCH_COUNT)
#include "mtk_enhance.h"
#endif

#if defined(MTK_LOGD_ENHANCE) && defined(CONFIG_MT_DEBUG_BUILD) && defined(MTK_LOGDW_SOCK_BLOCK)
#define SOCKET_TIME_OUT 2
#endif

static int logd_socket;
static RwLock logd_socket_lock;

static void OpenSocketLocked() {
#if defined(MTK_LOGD_ENHANCE) && defined(CONFIG_MT_DEBUG_BUILD) && defined(MTK_LOGDW_SOCK_BLOCK)
    /*
      *  Mtk enhance: create BLOCK mode socket and set Timeout.
      *  But filter out  process 'android.hardware.configstore@1.0-service' which
      *  does not has 'setsockopt' privilege.
      */
    int skip_thread = 0;
    FILE *fp;
    char path[PATH_MAX];
    char threadnamebuf[1024];
    char* threadname = NULL;
#if !defined(CONFIG_MT_ENG_BUILD)
    const char* key_camera = "camerahalserver";
#else
   const char* key_configstore = "android.hardware.configstore";
#endif

    snprintf(path, PATH_MAX, "/proc/%d/cmdline", getpid());
    if ((fp = fopen(path, "r"))) {
      threadname = fgets(threadnamebuf, sizeof(threadnamebuf), fp);
      fclose(fp);
    }
#if !defined(CONFIG_MT_ENG_BUILD)  // userdebug load
    skip_thread = 1;  // default skip block mode
    if (threadname && strstr(threadname, key_camera))
      skip_thread = 0;  // use block mode
#else  // eng load
    if (threadname && strstr(threadname, key_configstore))
      skip_thread = 1;  // set filter flag
#endif

    if (skip_thread == 0) {  // no need filter, create BLOCK mode socket
      logd_socket = TEMP_FAILURE_RETRY(
        socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    } else {
      logd_socket = TEMP_FAILURE_RETRY(
        socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    }
#else
    logd_socket = TEMP_FAILURE_RETRY(socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
#endif
  if (logd_socket <= 0) {
    return;
  }

  sockaddr_un un = {};
#if defined(MTK_LOGD_ENHANCE) && defined(CONFIG_MT_DEBUG_BUILD) && defined(MTK_LOGDW_SOCK_BLOCK)
      if (skip_thread == 0) {
        struct timeval tm;

        tm.tv_sec = SOCKET_TIME_OUT;
        tm.tv_usec = 0;
        if (setsockopt(logd_socket, SOL_SOCKET, SO_RCVTIMEO, &tm, sizeof(tm)) == -1 ||
          setsockopt(logd_socket, SOL_SOCKET, SO_SNDTIMEO, &tm, sizeof(tm)) == -1) {
          close(logd_socket);
          return;
        }
      }
#endif
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

void LogdClose() {
  auto lock = std::unique_lock{logd_socket_lock};
  if (logd_socket > 0) {
    close(logd_socket);
  }
  logd_socket = 0;
}

int LogdWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr) {
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
#if defined(MTK_LOGD_ENHANCE) && defined(ANDROID_LOG_MUCH_COUNT)
  bool tag_add = false;

  if ((logId != LOG_ID_EVENTS) && (nr == 3) && strstr((char*)vec[1].iov_base, "-0x")) {
      tag_add = true;
  }

#endif

  /* logd, after initialization and priv drop */
  if (getuid() == AID_LOGD) {
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
#if defined(MTK_LOGD_ENHANCE) && defined(ANDROID_LOG_MUCH_COUNT)
    if (tag_add == true) {
      if (payloadSize > (size_t)(LOGGER_ENTRY_MAX_PAYLOAD + tag_add_size)) {
        newVec[i].iov_len -= payloadSize - (size_t)(LOGGER_ENTRY_MAX_PAYLOAD + tag_add_size);
        if (newVec[i].iov_len) {
          ++i;
        }
        break;
      }
    } else if (payloadSize > LOGGER_ENTRY_MAX_PAYLOAD) {
      newVec[i].iov_len -= payloadSize - LOGGER_ENTRY_MAX_PAYLOAD;
      if (newVec[i].iov_len) {
        ++i;
      }
      break;
    }
#else
    if (payloadSize > LOGGER_ENTRY_MAX_PAYLOAD) {
      newVec[i].iov_len -= payloadSize - LOGGER_ENTRY_MAX_PAYLOAD;
      if (newVec[i].iov_len) {
        ++i;
      }
      break;
    }
#endif
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

#if defined(MTK_LOGD_ENHANCE) && defined(CONFIG_MT_DEBUG_BUILD) && defined(MTK_LOGDW_SOCK_BLOCK)
  if (ret == -EAGAIN) {
      ret = TEMP_FAILURE_RETRY(writev(logd_socket, newVec, i));
  }
#endif

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
#if defined(MTK_LOGD_ENHANCE) && defined(ANDROID_LOG_MUCH_COUNT)
  if (tag_add) {
    ret -= tag_add_size;
  }
#endif
  return ret;
}
