/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "log.h"

#include <fcntl.h>
#include <linux/audit.h>
#include <string.h>

#include <android-base/logging.h>
#include <netlink/netlink.h>
#include <selinux/selinux.h>

void InitKernelLogging(char* argv[]) {
    // Make stdin/stdout/stderr all point to /dev/null.
    int fd = open("/sys/fs/selinux/null", O_RDWR);
    if (fd == -1) {
        int saved_errno = errno;
        android::base::InitLogging(argv, &android::base::KernelLogger);
        errno = saved_errno;
        PLOG(FATAL) << "Couldn't open /sys/fs/selinux/null";
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if (fd > 2) close(fd);

    android::base::InitLogging(argv, &android::base::KernelLogger);
}

static void selinux_avc_log(char* buf, size_t buf_len) {
    size_t str_len = strnlen(buf, buf_len);

    // trim newline at end of string
    buf[str_len - 1] = '\0';

    struct nl_sock* sk = nl_socket_alloc();
    if (sk == NULL) {
        return;
    }
    nl_connect(sk, NETLINK_AUDIT);
    int result;
    do {
        result = nl_send_simple(sk, AUDIT_USER_AVC, 0, buf, str_len);
    } while (result == -NLE_INTR);
    nl_socket_free(sk);
}

int selinux_klog_callback(int type, const char *fmt, ...) {
    android::base::LogSeverity severity = android::base::ERROR;
    if (type == SELINUX_WARNING) {
        severity = android::base::WARNING;
    } else if (type == SELINUX_INFO) {
        severity = android::base::INFO;
    }
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int res = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (res <= 0) {
        return 0;
    }
    if (type == SELINUX_AVC) {
        selinux_avc_log(buf, sizeof(buf));
    } else {
        android::base::KernelLogger(android::base::MAIN, severity, "selinux", nullptr, 0, buf);
    }
    return 0;
}
