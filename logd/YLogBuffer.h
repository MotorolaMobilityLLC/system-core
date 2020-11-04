/*
 * Copyright (C) 2007-2017 The Android Open Source Project
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
#ifndef _YLOG_BUFFER_H__
#define _YLOG_BUFFER_H__

#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <sys/cdefs.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
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
#include <fcntl.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <log/log.h>
#include <log/log_read.h>
#include <log/log.h>
#include <log/logprint.h>
#include <log/event_tag_map.h>
#include <sys/sysinfo.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>
#include "CommandListener.h"
#include "LogCommand.h"
#include "LogUtils.h"
//#include "LogBufferInterface.h"
#include "LogBuffer.h"
#include "LogListener.h"
#include "LogBufferElement.h"
#include "LogReader.h"
#include "YLogBuffer.h"

using namespace std;

class LogBufferElement;

typedef int INSERT_YLOGBUFFER_CALLBACK(log_id_t log_id, log_time realtime,uid_t uid, pid_t pid, pid_t tid,const char *msg, unsigned short len);

class YLogBuffer {
public:
    static YLogBuffer* getInstance();
    void init();
    int log(LogBuffer* logbuf, log_id_t log_id, log_time realtime,uid_t uid, pid_t pid, pid_t tid,const char *msg, unsigned short len);
    int getLastLog(SocketClient* cli, int argc, char** argv);
private:
    static int insertCallback(log_id_t log_id, log_time realtime,uid_t uid, pid_t pid, pid_t tid,const char *msg, unsigned short len);
    void lockQueue(void);
    void unlockQueue(void);
    static void *BufferSenderThread(void *obj);
    void writeAndroidLog2Device(LogBufferElement* element);
    int sendDataLockedv(struct iovec *iov, int iovcnt);
    void directSend2Ylog(char* msg, int len);
    void * handelBuffer();
    unsigned char* getDeviceBuff(const char* path, long size);
    void write2LastAndroidRingBuffer(char* logmsg);
    int LogMsg2LogEntry(struct log_msg *msg, AndroidLogEntry *pEntry);
    int outputLogEntry(AndroidLogEntry *pEntry);
    void * runCMD(const char *cmd_para, SocketClient* cli);
    long readFileToMem(const char* file, char* result, long len);
    bool mLogID[LOG_ID_MAX];
    list<LogBufferElement*> mLogElementQueue[2];
    int mInQueueSizeMax = LOG_BUFFER_MIN_SIZE;
    int mInQueueSize = 0;
    int mInQueueIndex = 0;
    int mOutQueueIndex = 1;
    int mSendCount = 0;
    int mSocket;
    pthread_mutex_t mQueueLock = PTHREAD_MUTEX_INITIALIZER;
    int mLogUID = 0;
    int mLogcount;
    int mLostCount;
    bool mYlogRunning = false;
};
#endif
