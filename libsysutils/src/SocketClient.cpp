/*
 * Copyright (C) 2009-2016 The Android Open Source Project
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

#define LOG_TAG "SocketClient"

#include <alloca.h>
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <log/log.h>
#include <sysutils/SocketClient.h>

SocketClient::SocketClient(int socket, bool owned) {
    init(socket, owned, false);
}

SocketClient::SocketClient(int socket, bool owned, bool useCmdNum) {
    init(socket, owned, useCmdNum);
}

void SocketClient::init(int socket, bool owned, bool useCmdNum) {
    mSocket = socket;
    mSocketOwned = owned;
    mUseCmdNum = useCmdNum;
    pthread_mutex_init(&mWriteMutex, nullptr);
    pthread_mutex_init(&mRefCountMutex, nullptr);
    mPid = -1;
    mUid = -1;
    mGid = -1;
    mRefCount = 1;
    mCmdNum = 0;

    struct ucred creds;
    socklen_t szCreds = sizeof(creds);
    memset(&creds, 0, szCreds);

    int err = getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &creds, &szCreds);
    if (err == 0) {
        mPid = creds.pid;
        mUid = creds.uid;
        mGid = creds.gid;
    }
}

SocketClient::~SocketClient() {
    if (mSocketOwned) {
        close(mSocket);
    }
}

int SocketClient::sendMsg(int code, const char *msg, bool addErrno) {
    return sendMsg(code, msg, addErrno, mUseCmdNum);
}

int SocketClient::sendMsg(int code, const char *msg, bool addErrno, bool useCmdNum) {
    char *buf;
    int ret = 0;

    if (addErrno) {
        if (useCmdNum) {
            ret = asprintf(&buf, "%d %d %s (%s)", code, getCmdNum(), msg, strerror(errno));
        } else {
            ret = asprintf(&buf, "%d %s (%s)", code, msg, strerror(errno));
        }
    } else {
        if (useCmdNum) {
            ret = asprintf(&buf, "%d %d %s", code, getCmdNum(), msg);
        } else {
            ret = asprintf(&buf, "%d %s", code, msg);
        }
    }
    // Send the zero-terminated message
    if (ret != -1) {
        ret = sendMsg(buf);
        free(buf);
    }
    return ret;
}

// send 3-digit code, null, binary-length, binary data
int SocketClient::sendBinaryMsg(int code, const void *data, int len) {

    // 4 bytes for the code & null + 4 bytes for the len
    char buf[8];
    // Write the code
    snprintf(buf, 4, "%.3d", code);
    // Write the len
    uint32_t tmp = htonl(len);
    memcpy(buf + 4, &tmp, sizeof(uint32_t));

    struct iovec vec[2];
    vec[0].iov_base = (void *) buf;
    vec[0].iov_len = sizeof(buf);
    vec[1].iov_base = (void *) data;
    vec[1].iov_len = len;

    pthread_mutex_lock(&mWriteMutex);
    int result = sendDataLockedv(vec, (len > 0) ? 2 : 1);
    pthread_mutex_unlock(&mWriteMutex);

    return result;
}

// Sends the code (c-string null-terminated).
int SocketClient::sendCode(int code) {
    char buf[4];
    snprintf(buf, sizeof(buf), "%.3d", code);
    return sendData(buf, sizeof(buf));
}

char *SocketClient::quoteArg(const char *arg) {
    int len = strlen(arg);
    char *result = (char *)malloc(len * 2 + 3);
    char *current = result;
    const char *end = arg + len;
    char *oldresult;

    if(result == nullptr) {
        SLOGW("malloc error (%s)", strerror(errno));
        return nullptr;
    }

    *(current++) = '"';
    while (arg < end) {
        switch (*arg) {
        case '\\':
        case '"':
            *(current++) = '\\';
            FALLTHROUGH_INTENDED;
        default:
            *(current++) = *(arg++);
        }
    }
    *(current++) = '"';
    *(current++) = '\0';
    oldresult = result; // save pointer in case realloc fails
    result = (char *)realloc(result, current-result);
    return result ? result : oldresult;
}


int SocketClient::sendMsg(const char *msg) {
    // Send the message including null character
    if (sendData(msg, strlen(msg) + 1) != 0) {
        SLOGW("Unable to send msg '%s'", msg);
        return -1;
    }
    return 0;
}

int SocketClient::sendData(const void *data, int len) {
    struct iovec vec[1];
    vec[0].iov_base = (void *) data;
    vec[0].iov_len = len;

    pthread_mutex_lock(&mWriteMutex);
    int rc = sendDataLockedv(vec, 1);
    pthread_mutex_unlock(&mWriteMutex);

    return rc;
}

int SocketClient::sendDatav(struct iovec *iov, int iovcnt) {
    pthread_mutex_lock(&mWriteMutex);
    int rc = sendDataLockedv(iov, iovcnt);
    pthread_mutex_unlock(&mWriteMutex);

    return rc;
}

int SocketClient::sendDataLockedv(struct iovec *iov, int iovcnt) {

    if (mSocket < 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    if (iovcnt <= 0) {
        return 0;
    }

    int ret = 0;
    int e = 0; // SLOGW and sigaction are not inert regarding errno
    int current = 0;

    struct sigaction new_action, old_action;
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &new_action, &old_action);

    for (;;) {
        ssize_t rc = TEMP_FAILURE_RETRY(
            writev(mSocket, iov + current, iovcnt - current));

        if (rc > 0) {
            size_t written = rc;
            while ((current < iovcnt) && (written >= iov[current].iov_len)) {
                written -= iov[current].iov_len;
                current++;
            }
            if (current == iovcnt) {
                break;
            }
            iov[current].iov_base = (char *)iov[current].iov_base + written;
            iov[current].iov_len -= written;
            continue;
        }

        if (rc == 0) {
            e = EIO;
            SLOGW("0 length write :(");
        } else {
            e = errno;
            SLOGW("write error (%s)", strerror(e));
        }
        ret = -1;
        break;
    }

    sigaction(SIGPIPE, &old_action, &new_action);

    if (e != 0) {
        errno = e;
    }
    return ret;
}

void SocketClient::incRef() {
    pthread_mutex_lock(&mRefCountMutex);
    mRefCount++;
    pthread_mutex_unlock(&mRefCountMutex);
}

bool SocketClient::decRef() {
    bool deleteSelf = false;
    pthread_mutex_lock(&mRefCountMutex);
    mRefCount--;
    if (mRefCount == 0) {
        deleteSelf = true;
    } else if (mRefCount < 0) {
        SLOGE("SocketClient refcount went negative!");
    }
    pthread_mutex_unlock(&mRefCountMutex);
    if (deleteSelf) {
        delete this;
    }
    return deleteSelf;
}
