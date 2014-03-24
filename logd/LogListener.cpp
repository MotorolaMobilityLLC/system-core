/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <cutils/sockets.h>
#include <log/logger.h>

#include "LogListener.h"

LogListener::LogListener(LogBuffer *buf, LogReader *reader)
        : SocketListener(getLogSocket(), false)
        , logbuf(buf)
        , reader(reader)
{  }

bool LogListener::onDataAvailable(SocketClient *cli) {
    char buffer[sizeof_log_id_t + sizeof(log_time) + sizeof(char)
        + LOGGER_ENTRY_MAX_PAYLOAD];
    struct iovec iov = { buffer, sizeof(buffer) };
    memset(buffer, 0, sizeof(buffer));

    char control[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr hdr = {
        NULL,
        0,
        &iov,
        1,
        control,
        sizeof(control),
        0,
    };

    int socket = cli->getSocket();

    ssize_t n = recvmsg(socket, &hdr, 0);
    if (n <= (sizeof_log_id_t + sizeof(uint16_t) + sizeof(log_time))) {
        return false;
    }

    struct ucred *cred = NULL;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
    while (cmsg != NULL) {
        if (cmsg->cmsg_level == SOL_SOCKET
                && cmsg->cmsg_type  == SCM_CREDENTIALS) {
            cred = (struct ucred *)CMSG_DATA(cmsg);
            break;
        }
        cmsg = CMSG_NXTHDR(&hdr, cmsg);
    }

    if (cred == NULL) {
        return false;
    }

    if (cred->uid == getuid()) {
        // ignore log messages we send to ourself.
        // Such log messages are often generated by libraries we depend on
        // which use standard Android logging.
        return false;
    }

    // First log element is always log_id.
    log_id_t log_id = (log_id_t) *((typeof_log_id_t *) buffer);
    if (log_id < 0 || log_id >= LOG_ID_MAX) {
        return false;
    }
    char *msg = ((char *)buffer) + sizeof_log_id_t;
    n -= sizeof_log_id_t;

    // second element is the thread id of the caller
    pid_t tid = (pid_t) *((uint16_t *) msg);
    msg += sizeof(uint16_t);
    n -= sizeof(uint16_t);

    // third element is the realtime at point of caller
    log_time realtime(msg);
    msg += sizeof(log_time);
    n -= sizeof(log_time);

    // NB: hdr.msg_flags & MSG_TRUNC is not tested, silently passing a
    // truncated message to the logs.
    unsigned short len = n; // cap to internal maximum
    if (len == n) {
        logbuf->log(log_id, realtime, cred->uid, cred->pid, tid, msg, len);
        reader->notifyNewLog();
    }

    return true;
}

int LogListener::getLogSocket() {
    int sock = android_get_control_socket("logdw");
    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
        return -1;
    }
    return sock;
}
