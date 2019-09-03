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
#include <cutils/sockets.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>
#include "LogUtils.h"
#include <queue>
#include <list>

using namespace std;
#define DEBUG_

class LogBufferElement;

class YLogBuffer {
    bool mLogID[LOG_ID_MAX];
	static list<LogBufferElement*> mLogElementQueue[2];
    static int mInQueueSizeMax;
    static int mInQueueSize;

    static int mInQueueIndex ;
    static int mOutQueueIndex;

    static int mSendCount;
    static int mSocket;
    static pthread_mutex_t mQueueLock;
    static int mLogUID;

    static int mLogcount;
    static int mLostCount;
#ifdef DEBUG_
    static int mLogWorking;
    static int mSocketWorking;
    static string mLog;
#endif
  static unsigned long GetTime();
  public :
    static void init( );
    static void print( string & output);
    static void lockQueue(void) ;
    static void unlockQueue(void);
    static int log(    LogBuffer* logbuf,log_id_t log_id, log_time realtime,
                   uid_t uid, pid_t pid, pid_t tid,
                   const char *msg, unsigned short len);
     static int logFromLogd(log_id_t log_id, log_time realtime,
                   uid_t uid, pid_t pid, pid_t tid,
                   const char *msg, unsigned short len);

    static void *BufferSender(void *obj) ;
    static int sendDataLockedv(struct iovec *iov, int iovcnt);
    static void printLog(char* msg,int len);
};
#endif
