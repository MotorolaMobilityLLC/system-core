/*
 * Copyright (C) 2007-2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *f
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/cdefs.h>
#include <sys/un.h>
#include <endian.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <android-base/stringprintf.h>
#include <private/android_filesystem_config.h>
#include <sysutils/SocketClient.h>
#include <private/android_logger.h>
#include <utils/threads.h>
#include <cutils/properties.h>
#include <string>
#include <queue>
#include <iostream>
#include <fstream>
#include "CommandListener.h"
#include "LogCommand.h"
#include "LogUtils.h"
//#include "LogBufferInterface.h"

#include <sys/types.h>

#include <list>
#include <string>

#include <android/log.h>
#include <private/android_filesystem_config.h>
#include <sysutils/SocketClient.h>

#include "LogBufferElement.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "LogTimes.h"
#include "LogWhiteBlackList.h"
#include "LogBuffer.h"
#include "LogListener.h"
#include "LogBufferElement.h"
#include "LogReader.h"
#include "YLogBuffer.h"

//#define DO_LOG_LASTANDROID


#define log2kernel(...)  {char buff[1024]={0};snprintf(buff,sizeof(buff)-1,__VA_ARGS__);android::prdebug("logd: %s ",buff);}

#define  YLOG_BUFFER_SIZE (4*1024*1024) //4M
#define  YLOG_BUFFER_MIN_SIZE (1*1024*1024) //1M
#define SEND_PERIOD (100*1000) //100ms
#define DATA_THRESHOLD (10*1024) //10K
#define MAX_LOGUID (0xFFFFFF)
#define LASTANDROID_DEVICE "/dev/ylog_buffer"
#define LASTANDROID_BUF_SIZE (1 * 1024 * 1024)
#define DEBUG_CHAR ' '

YLogBuffer* YLogBuffer::getInstance() {
    static YLogBuffer mInstance;
    return &mInstance;
}

void YLogBuffer::lockQueue(void) {
    pthread_mutex_lock(&mQueueLock);
}

void YLogBuffer::unlockQueue(void) {
    pthread_mutex_unlock(&mQueueLock);
}

int YLogBuffer::insertCallback(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid, const char *msg, unsigned short len) {
    uid;
    LogBufferElement *element = new LogBufferElement(log_id, realtime, 1, pid, tid, msg, len);
    YLogBuffer::getInstance()->mLogElementQueue[YLogBuffer::getInstance()->mInQueueIndex].push_back(element);
    return 0;
}

int YLogBuffer::log(LogBuffer* logbuf, log_id_t log_id, log_time realtime,
        uid_t uid, pid_t pid, pid_t tid,
        const char *msg, unsigned short len) {
    uid;
    logbuf;
    static int ofe_count = 0;
    LogBufferElement *element = new LogBufferElement(log_id, realtime, mLogUID++, pid, tid, msg, len);

#if defined(DO_LOG_LASTANDROID)
    writeAndroidLog2Device(element);
#endif

    if (!mYlogRunning) {
        delete element;
        return 0;
    }

    if (mLogUID >= MAX_LOGUID) {
        mLogUID = 0;
    }

    if (0 == mLogcount) {
        lockQueue();
        LogBuffer* buf = (LogBuffer*) logbuf;
        mLogcount = buf->copy2ylogbuffer(insertCallback);
        unlockQueue();
        log2kernel("copy logs  from logd buffer:%d", mLogcount);
    }

    mLogcount++;

    lockQueue();
    mLogElementQueue[mInQueueIndex].push_back(element);
    mInQueueSize += element->mMsgLen;
    if (mInQueueSize >= mInQueueSizeMax) {
        int i = 0;
        int dropCount = mInQueueSizeMax / (1024 * 4);
        int suid = 0;
        int euid = 0;
        list<LogBufferElement*>::iterator iter = mLogElementQueue[mInQueueIndex].begin();
        while (!mLogElementQueue[mInQueueIndex].empty()) {
            if (i >= dropCount) {
                break;
            }
            LogBufferElement* pushe = *iter;
            mInQueueSize -= pushe->mMsgLen;
            if (0 == i) {
                suid = pushe->mUid;
            }
            euid = pushe->mUid;
            iter = mLogElementQueue[mInQueueIndex].erase(iter);
            delete pushe;
            i++;
        }
        mLostCount += dropCount;
        ofe_count++;
        if (0 == (ofe_count % 100)) {
            log2kernel("overflow:%d(%d)->%d(%d) q:%d[%d->%d] [%d %06X-%06X] %d", mLogcount, -1, mSendCount, -1, mInQueueSize, mInQueueIndex, mOutQueueIndex, mLostCount, suid, euid, ofe_count);
            if (mSocket >= 0) {
                close(mSocket);
                mSocket = 0;
            }
        }
        mLostCount = 0;
    }
    unlockQueue();

    return 0;
};

void YLogBuffer::directSend2Ylog(char* msg, int len) {
    struct logger_entry entry;
    memset(&entry, 0, sizeof (struct logger_entry));
    entry.hdr_size = sizeof (struct logger_entry);
    entry.lid = LOG_ID_SYSTEM;
    entry.pid = getpid();
    entry.tid = gettid();
    entry.uid = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    entry.sec = ts.tv_sec;
    entry.nsec = ts.tv_nsec;

    struct iovec iovec[2];
    iovec[0].iov_base = &entry;
    iovec[0].iov_len = entry.hdr_size;

    char *buffer = NULL;
    const char* mMsg = msg;
    entry.len = len;
    iovec[1].iov_base = (void*) mMsg;
    iovec[1].iov_len = entry.len;
    YLogBuffer::sendDataLockedv(iovec, 2);
}

void * YLogBuffer::BufferSenderThread(void *obj) {
    prctl(PR_SET_NAME, "logd.ylog");
    YLogBuffer* pYLogBuffer = (YLogBuffer*) obj;
    return pYLogBuffer->handelBuffer();
}

void * YLogBuffer::handelBuffer() {
    static const char socketName[] = "logdylog";
    int lsocket = android_get_control_socket(socketName);
    log2kernel("get socket :%d", lsocket);
    listen(lsocket, 5);
    log2kernel("listening.......");
    struct sockaddr addr;
    socklen_t alen=sizeof(addr);
    unsigned long lastSendStartTime = 0;
    mYlogRunning = false;
    int reConnectCount = 0;
    int retryWriteCount = 0;
RECONNECT:
    retryWriteCount = 0;
    log2kernel("accept...");
    int s = accept(lsocket, &addr, &alen);
    reConnectCount++;
    log2kernel("accept:%d", s);

    if (-1 == s) {
        sleep(5);
        goto RECONNECT;
    }
    mYlogRunning = true;
    mSocket = s;
    int suid = 0, euid = 0;

    char debugMsg[512] = {0};
    int len = sprintf(debugMsg, "%s", " LOGD");
    int len2 = sprintf(debugMsg + len + 1, "ylog  connnect %d! logCount:%d sendCcount:%d recSize:%d  %d->%d               ", reConnectCount, mLogcount, mSendCount, mInQueueSize, mInQueueIndex, mOutQueueIndex);
    directSend2Ylog(debugMsg, len + len2 + 1);

    int queueSize = 0;
    do {
        int n = mLogElementQueue[mOutQueueIndex].size();
        for (int i = 0; i < n; i++) {
            LogBufferElement* element = mLogElementQueue[mOutQueueIndex].front();
            if (i == 0) {
                suid = element->mUid;
            }
            euid = element->mUid;
            struct logger_entry entry;
            memset(&entry, 0, sizeof (struct logger_entry));
            entry.hdr_size = sizeof (struct logger_entry);
            entry.lid = element->mLogId;
            entry.pid = element->mPid;
            entry.tid = element->mTid;
            entry.uid = element->mUid;
            entry.sec = element->mRealTime.tv_sec;
            entry.nsec = element->mRealTime.tv_nsec;

            struct iovec iovec[2];
            iovec[0].iov_base = &entry;
            iovec[0].iov_len = entry.hdr_size;
            char *buffer = NULL;
            const char* mMsg = element->mMsg;
            entry.len = element->mMsgLen;
            iovec[1].iov_base = (void*) mMsg;
            iovec[1].iov_len = entry.len;

REWRITE:
            retryWriteCount = 0;
            int retval = YLogBuffer::sendDataLockedv(iovec, 2);
            if (-1 == retval) {
                int e = errno;
                if ((e == EBUSY) || (e == EAGAIN)) {
                    usleep(1000);
                    retryWriteCount++;
                    if (retryWriteCount < 2000) {
                        goto REWRITE;
                    }
                }
                if (mSocket >= 0) {
                    close(mSocket);
                }

                log2kernel("swe:%d(%d)->%d(%d) q:%d[%d->%d]  err=%d %d", mLogcount, -1, mSendCount, -1, queueSize, mInQueueIndex, mOutQueueIndex, e, retryWriteCount);
                goto RECONNECT;
            }
            mLogElementQueue[mOutQueueIndex].pop_front();
            delete element;
        }

        mSendCount++;

        lockQueue();
        int tmpIndex = mInQueueIndex;
        mInQueueIndex = mOutQueueIndex;
        mOutQueueIndex = tmpIndex;
        queueSize = mInQueueSize;
        mInQueueSize = 0;
        unlockQueue();

        if (queueSize < DATA_THRESHOLD) {
            usleep(SEND_PERIOD);
        }
    } while (true);
    return NULL;
}

void YLogBuffer::init() {
    mInQueueSizeMax = property_get_bool("ro.config.low_ram",
            BOOL_DEFAULT_FALSE)
            ? YLOG_BUFFER_MIN_SIZE
            : YLOG_BUFFER_SIZE;

    pthread_attr_t attr;
    static pthread_t threadid;
    if (!pthread_attr_init(&attr)) {
        if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
            if (!pthread_create(&threadid, &attr, YLogBuffer::BufferSenderThread, this)) {
                pthread_attr_destroy(&attr);
                return;
            }
        }
        pthread_attr_destroy(&attr);
    };
};

//cp from SocketClient::sendDataLockedv(struct iovec *iov, int iovcnt)

int YLogBuffer::sendDataLockedv(struct iovec *iov, int iovcnt) {
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
    memset(&new_action, 0, sizeof (new_action));
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
            iov[current].iov_base = (char *) iov[current].iov_base + written;
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

unsigned char* YLogBuffer::getDeviceBuff(const char* path, long size) {
    int fd;
    unsigned char *pMap;

    fd = open(path, O_RDWR);
    int er = errno;
    if (fd < 0) {
        log2kernel("logd open %s  error:%s", path, strerror(er));
        return NULL;
    }

    pMap = (unsigned char *) mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pMap == MAP_FAILED) {
        log2kernel("logd  mmap %s  error ", path);
        close(fd);
        return NULL;
    }
    close(fd);
    log2kernel("logd  getDeviceBuff %s  =%p ok ", path, (void*) pMap);
    return pMap;
}

void YLogBuffer::write2LastAndroidRingBuffer(char* logmsg) {
    const long THRESHOLD = LASTANDROID_BUF_SIZE - LOGGER_ENTRY_MAX_LEN * 10;
    const long STEP = LASTANDROID_BUF_SIZE * 0.2;

    int len = strlen(logmsg);
    static unsigned char* pMem = NULL;
    if (NULL == pMem) {
        pMem = getDeviceBuff(LASTANDROID_DEVICE, LASTANDROID_BUF_SIZE);
        if (NULL != pMem) {
            memset(pMem, DEBUG_CHAR, LASTANDROID_BUF_SIZE);
        }
    }
    static long dataLength = 0;
    if (pMem != NULL) {
        if ((dataLength + len) >= THRESHOLD) {
            dataLength -= STEP;
            memmove(pMem, pMem + STEP, dataLength);
            memset(pMem + dataLength, DEBUG_CHAR, LASTANDROID_BUF_SIZE - dataLength);
        }
        memcpy(pMem + dataLength, logmsg, len);
        dataLength += len;
    }
}

int YLogBuffer::LogMsg2LogEntry(struct log_msg *msg, AndroidLogEntry *pEntry) {
    int err;
    static char binaryMsgBuf[1024];
    struct logger_entry *logEntry = (struct logger_entry *) msg;
    if (LOG_ID_EVENTS == logEntry->lid) {
        static bool hasOpenedEventTagMap = false;
        static EventTagMap *eventTagMap = NULL;
        if (!eventTagMap && !hasOpenedEventTagMap) {
            eventTagMap = android_openEventTagMap(EVENT_TAG_MAP_FILE);
            hasOpenedEventTagMap = true;
        }
        err = android_log_processBinaryLogBuffer
                (
                &msg->entry,
                pEntry,
                eventTagMap,
                binaryMsgBuf,
                sizeof (binaryMsgBuf)
                );
    } else {
        err = android_log_processLogBuffer(&msg->entry, pEntry);
    }

    if (err < 0) {
        if (LOG_ID_EVENTS == logEntry->lid) {
            android::prdebug("logd  pid:%d tid:%d android_log_processBinaryLogBuffer error\n", logEntry->pid, logEntry->tid);
        } else {
            android::prdebug("logd  pid:%d tid:%d android_log_processLogBuffer error\n", logEntry->pid, logEntry->tid);
        }
        return 0;
    }
    return 1;
}

int YLogBuffer::outputLogEntry(AndroidLogEntry *pEntry) {
    char defaultBuffer[512] = {0};
    char *outBuffer = NULL;
    char buf[10240] = {0};
    size_t totalLen;

    static AndroidLogFormat *androidLogFormat = NULL;
    if (NULL == androidLogFormat) {
        androidLogFormat = android_log_format_new();
        AndroidLogPrintFormat format = android_log_formatFromString("threadtime");
        android_log_setPrintFormat(androidLogFormat, format);
    }

    outBuffer = android_log_formatLogLine
            (
            androidLogFormat,
            defaultBuffer,
            sizeof (defaultBuffer),
            pEntry,
            &totalLen
            );
    if (totalLen > 10000) {
        if ((outBuffer != NULL)&&(outBuffer != defaultBuffer)) {
            free(outBuffer);
        }
        return -1;
    }

    static int uid = 0;
    if (outBuffer != NULL) {
        int len = snprintf(buf, sizeof (buf) - 1, "G%06X ", uid++);
        memcpy((void *) (buf + len), (void *) outBuffer, totalLen);
    } else {
        return 0;
    }
    write2LastAndroidRingBuffer(buf);
    if (outBuffer != defaultBuffer) {
        free(outBuffer);
    }
    return 0;
}

void YLogBuffer::writeAndroidLog2Device(LogBufferElement* element) {
    static unsigned char logData[LOGGER_ENTRY_MAX_LEN];

    struct logger_entry* pLoggerEntry = (struct logger_entry*) logData;
    memset(pLoggerEntry, 0, sizeof (logData));

    pLoggerEntry->hdr_size = sizeof (struct logger_entry);
    pLoggerEntry->lid = element->mLogId;
    pLoggerEntry->pid = element->mPid;
    pLoggerEntry->tid = element->mTid;
    pLoggerEntry->uid = element->mUid;
    pLoggerEntry->sec = element->mRealTime.tv_sec;
    pLoggerEntry->nsec = element->mRealTime.tv_nsec;
    pLoggerEntry->len = element->mMsgLen;
    memcpy((char*) pLoggerEntry + pLoggerEntry->hdr_size, element->mMsg, element->mMsgLen);

    AndroidLogEntry androidLogEntry;
    int ret = LogMsg2LogEntry((struct log_msg *) pLoggerEntry, &androidLogEntry);
    if (1 == ret) {
        outputLogEntry(&androidLogEntry);
    }
}

void *YLogBuffer::runCMD(const char *cmd_para, SocketClient* cli) {
#define BUF_SIZE 4096
    char *cmd = (char*) cmd_para;
    char buf[BUF_SIZE];
    FILE *file;

    file = popen(cmd, "r");
    if (file != NULL) {
        do {
            memset(buf, '\0', sizeof (buf));
            int len = 0;
            if ((len = fread(buf, sizeof (char), sizeof (buf) - 1, file)) <= 0) {
                break;
            }
            cli->sendData(buf, len);
        } while (!feof(file));
        pclose(file);
    }
    return NULL;
}

long YLogBuffer::readFileToMem(const char* file, char* result, long len) {
    FILE *fp = fopen(file, "r");
    long fileSize = -1;
    if (fp != NULL) {
        fseek(fp, 0L, SEEK_END);
        fileSize = ftell(fp);
        if (fileSize < 0){
          fileSize = 0;
        }
        if (fileSize >= len){
          fileSize = len - 1;
        }
        int ret=fseek(fp, -1 * fileSize, SEEK_CUR);
        if ((-1!=ret)&&(fileSize > 0)) {
            ret=fread(result, fileSize, 1, fp);
            if(ret!=fileSize){
              android::prdebug("readFileToMem err");
            }
        }
        fclose(fp);
    } else {
        sprintf(result, "open %s err %d", file, errno);
    }
    return fileSize;
}

int YLogBuffer::getLastLog(SocketClient* cli, int argc, char** argv) {
    const int LOGDATA_SIZE = 1024 * 200;
    char *buff = (char*) calloc(LOGDATA_SIZE, 1);
    char logfile[256] = "NULL";
    argc;

    switch (atoi(argv[1])) {
        case 0:
            strcpy(logfile, "/sys/fs/pstore/console-ramoops-0");
            break;
        case 1:
            strcpy(logfile, "/sys/fs/pstore/dmesg-ramoops-0");
            break;
        default:
            break;
    }

    if (atoi(argv[1]) == 2) {
        runCMD("logcat -L", cli);
    } else {
        long len = readFileToMem(logfile, buff, LOGDATA_SIZE - 1);
        cli->sendData(buff, len);
    }

    free(buff);
    return 0;
}
