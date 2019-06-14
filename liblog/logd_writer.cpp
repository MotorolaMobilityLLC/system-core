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

#include <endian.h>
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

#include "config_write.h"
#include "log_portability.h"
#include "logger.h"
#include "uio.h"

#if defined(MTK_LOGD_ENHANCE) && defined(ANDROID_LOG_MUCH_COUNT)
#include "mtk_enhance.h"
#endif

#if defined(MTK_LOGD_ENHANCE) && defined(CONFIG_MT_DEBUG_BUILD) && defined(MTK_LOGDW_SOCK_BLOCK)
#define SOCKET_TIME_OUT 2
#endif

/* branchless on many architectures. */
#define min(x, y) ((y) ^ (((x) ^ (y)) & -((x) < (y))))

static int logdAvailable(log_id_t LogId);
static int logdOpen();
static void logdClose();
static int logdWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr);

struct android_log_transport_write logdLoggerWrite = {
    .node = {&logdLoggerWrite.node, &logdLoggerWrite.node},
    .context.sock = -EBADF,
    .name = "logd",
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
    const char* key_configstore = "android.hardware.configstore";
#if !defined(CONFIG_MT_ENG_BUILD)
    const char* key_camera = "camerahalserver";
#endif
    int sock = -1;

    snprintf(path, PATH_MAX, "/proc/%d/cmdline", getpid());
    if((fp = fopen(path, "r"))) {
      threadname = fgets(threadnamebuf, sizeof(threadnamebuf), fp);
      fclose(fp);
    }
#if !defined(CONFIG_MT_ENG_BUILD) // userdebug load
    skip_thread = 1; // default skip block mode
    if (threadname && strstr(threadname, key_camera))
      skip_thread = 0; // use block mode
#else // eng load
    if (threadname && strstr(threadname, key_configstore))
      skip_thread = 1; // set filter flag
#endif

    if (skip_thread == 0) {  // no need filter, create BLOCK mode socket
      sock = TEMP_FAILURE_RETRY(
        socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    } else {
      sock = TEMP_FAILURE_RETRY(
        socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    }
#else
    int sock = TEMP_FAILURE_RETRY(socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
#endif
    if (sock < 0) {
      ret = -errno;
    } else {
      struct sockaddr_un un;
#if defined(MTK_LOGD_ENHANCE) && defined(CONFIG_MT_DEBUG_BUILD) && defined(MTK_LOGDW_SOCK_BLOCK)
      if (skip_thread == 0) {
        struct timeval tm;

        tm.tv_sec = SOCKET_TIME_OUT;
        tm.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tm, sizeof(tm)) == -1 ||
          setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tm, sizeof(tm)) == -1) {
          ret = -errno;
          close(sock);
          return ret;
        }
      }
#endif
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
#if defined(MTK_LOGD_ENHANCE) && defined(ANDROID_LOG_MUCH_COUNT)
  bool tag_add = false;

  if ((logId != LOG_ID_EVENTS) && (nr == 3) && strstr((char*)vec[1].iov_base, "-0x")) {
      tag_add = true;
  }

#endif

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

  /*
   *  struct {
   *      // what we provide to socket
   *      android_log_header_t header;
   *      // caller provides
   *      union {
   *          struct {
   *              char     prio;
   *              char     payload[];
   *          } string;
   *          struct {
   *              uint32_t tag
   *              char     payload[];
   *          } binary;
   *      };
   *  };
   */

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
      buffer.header.tag = htole32(LIBLOG_LOG_TAG);
      buffer.payload.type = EVENT_TYPE_INT;
      buffer.payload.data = htole32(snapshot);

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
      buffer.header.tag = htole32(LIBLOG_LOG_TAG);
      buffer.payload.type = EVENT_TYPE_INT;
      buffer.payload.data = htole32(snapshot);

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

#if defined(MTK_LOGD_ENHANCE) && defined(CONFIG_MT_DEBUG_BUILD) && defined(MTK_LOGDW_SOCK_BLOCK)
  if (ret == -EAGAIN) {
      ret = TEMP_FAILURE_RETRY(writev(atomic_load(&logdLoggerWrite.context.sock), newVec, i));
      if (ret < 0) {
          ret = -errno;
      }
  }
#endif

  if (ret > (ssize_t)sizeof(header)) {
    ret -= sizeof(header);
  } else if (ret == -EAGAIN) {
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
