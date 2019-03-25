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
#include "LogBufferInterface.h"
#include "LogBuffer.h"
#include "LogListener.h"
#include "LogBufferElement.h"
#include "LogReader.h"
#include "YLogBuffer.h"

#ifdef DEBUG_
#define YPRINTF(...)  {char buff[1024]={0};snprintf(buff,sizeof(buff)-1,__VA_ARGS__);android::prdebug("logd: %s ",buff);}

string YLogBuffer::mLog;
int YLogBuffer:: mLogWorking=0;
int YLogBuffer:: mSocketWorking =0;
float recspeed=0;
bool mYlogRunning=false;
#else
#define YPRINTF(...)
#endif

#define  YLOG_BUFFER_SIZE (4*1024*1024) //4M
#define  YLOG_BUFFER_MIN_SIZE (1*1024*1024) //1M
#define SEND_PERIOD (100*1000) //100ms
#define DATA_THRESHOLD (10*1024) //10K
#define MAX_LOGUID (0xFFFFFF)

list<LogBufferElement*> YLogBuffer::mLogElementQueue[2];
int YLogBuffer::mInQueueSizeMax=LOG_BUFFER_MIN_SIZE;
int YLogBuffer::mInQueueSize=0;

int YLogBuffer::mInQueueIndex =0;
int YLogBuffer::mOutQueueIndex=1;

int YLogBuffer:: mLogcount =0;
int YLogBuffer::mSendCount=0;
int YLogBuffer::mSocket;

int YLogBuffer:: mLogUID=0;
static int mMallocCount=0;
static int mInQueueFreeCount=0;
static int mOutQueueFreeCount=0;
int mLogdMallocCount=0;
int mLogdFreeCount=0;

pthread_mutex_t YLogBuffer::mQueueLock=PTHREAD_MUTEX_INITIALIZER;

int YLogBuffer::mLostCount=0;

void YLogBuffer:: print( string & output) {
    output;
}

void YLogBuffer::lockQueue(void) {
    pthread_mutex_lock(&mQueueLock);
}

void YLogBuffer::unlockQueue(void) {
    pthread_mutex_unlock(&mQueueLock);
}

int YLogBuffer::logFromLogd(log_id_t log_id, log_time realtime,
                    uid_t uid, pid_t pid, pid_t tid,
                    const char *msg, unsigned short len) {

    uid;
    LogBufferElement *element=new LogBufferElement(log_id, realtime,1, pid, tid, msg, len);
    mLogElementQueue[mInQueueIndex].push_back(element);
    return 0;

}

int YLogBuffer::log(    LogBuffer* logbuf,log_id_t log_id, log_time realtime,
                    uid_t uid, pid_t pid, pid_t tid,
                    const char *msg, unsigned short len) {

    uid;
    mLogWorking=1;
    static int ofe_count=0;

    if (!mYlogRunning) {
        return 0;
    }

    LogBufferElement *element=new LogBufferElement(log_id, realtime,mLogUID++, pid, tid, msg, len);
    mMallocCount++;
    if (mLogUID>=MAX_LOGUID) {
        mLogUID=0;
    }

    if(0==mLogcount){
        lockQueue();
        LogBuffer* buf=(LogBuffer*)logbuf;
        mLogcount=buf->copy2ylogbuffer();
         unlockQueue();
         YPRINTF("copy logs  from logd buffer:%d",mLogcount);
    }

    mLogcount++;

    lockQueue();
    mLogWorking=2;

    mLogElementQueue[mInQueueIndex].push_back(element);

    mInQueueSize+=element->mMsgLen;

    if(mInQueueSize>=mInQueueSizeMax) {
        int i=0;
        int dropCount=mInQueueSizeMax/(1024*4);
        int suid=0;
        int euid=0;
        list<LogBufferElement*>::iterator iter = mLogElementQueue[mInQueueIndex].begin();


        while(!mLogElementQueue[mInQueueIndex].empty()) {
            if(i>=dropCount)break;
            LogBufferElement* pushe=*iter;
            if(0==pushe->mPid) {
                //std::advance(iter, 1);
                //continue;
            }
            mInQueueSize-=pushe->mMsgLen;
            if(i==0)suid=pushe->mUid;
            euid=pushe->mUid;
            iter=mLogElementQueue[mInQueueIndex].erase (iter);
            delete pushe;
            mInQueueFreeCount++;
            i++;
        }
        mLostCount+=dropCount;
        ofe_count++;

        {
            log_time now;
            now = log_time(CLOCK_REALTIME);
            if(0==(ofe_count%100)){
               YPRINTF("overflow:%d(%d)->%d(%d) q:%d[%d->%d] [%d %06X-%06X] %d",mLogcount,mLogWorking,mSendCount,mSocketWorking,mInQueueSize,mInQueueIndex,mOutQueueIndex,mLostCount,suid,euid,ofe_count);
                if(mSocket>=0){
                    close(mSocket);
                    mSocket=0;
                }
            }

        }
        mLostCount=0;
    }
    unlockQueue();
    mLogWorking=3;
    return 0;
};


unsigned long YLogBuffer::GetTime()  {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000*1000 + ts.tv_nsec / 1000);
}


void * YLogBuffer::BufferSender(void *obj) {
    prctl(PR_SET_NAME, "logd.ylog");
    obj;

    static const char socketName[] = "logdylog";
    int  lsocket = android_get_control_socket(socketName);
    YPRINTF("get socket :%d",lsocket);
    listen(lsocket, 5);
    YPRINTF("listening.......");
    struct sockaddr addr;
    socklen_t alen;
    unsigned long lastSendStartTime=0;
    mYlogRunning=false;
    int reConnectCount=0;
    int retryWriteCount=0;
RECONNECT:
    retryWriteCount=0;
    YPRINTF("accept...");
    mSocketWorking=1;

    int  s = accept(lsocket, &addr, &alen);
    reConnectCount++;
    YPRINTF("accept:%d",s);

    if(-1==s){
        sleep(5);
        goto RECONNECT ;
    }
    mYlogRunning=true;
    mSocket=s;
    int suid=0,euid=0;

    int  queueSize=0;
    do {
        unsigned long nowTime=GetTime();
        recspeed=-1;
        if((nowTime - lastSendStartTime)>0) {
            if(queueSize>DATA_THRESHOLD) {
                recspeed=queueSize*1.0000001/1024/1024/((nowTime - lastSendStartTime)*1.0000001/1000/1000);
            }
        }
        lastSendStartTime=nowTime;


        int n=mLogElementQueue[mOutQueueIndex].size();
        for(int i=0; i<n; i++) {
            LogBufferElement* element=mLogElementQueue[mOutQueueIndex].front();

            if(i==0)suid=element->mUid;
            euid=element->mUid;
            struct logger_entry_v4 entry;
            memset(&entry, 0, sizeof(struct logger_entry_v4));

            entry.hdr_size =sizeof(struct logger_entry_v4) ;
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
            const char* mMsg= element->mMsg;
            entry.len = element->mMsgLen;
            iovec[1].iov_base =(void*) mMsg;
            iovec[1].iov_len = entry.len;

REWRITE:
            mSocketWorking=2;
            retryWriteCount=0;
            int retval = YLogBuffer::sendDataLockedv(iovec, 2) ;
            mSocketWorking=3;
            if(-1==retval) {
                int e = errno;
                if ((e == EBUSY)||(e == EAGAIN)) {
                    usleep(1000);
                    retryWriteCount++;
                    if(retryWriteCount<2000){
                        goto REWRITE;
                    }
                }
                if(mSocket>=0){
                    close(mSocket);
                }
                mSocketWorking=-1;
                YPRINTF("swe:%d(%d)->%d(%d) q:%d[%d->%d]  err=%d %d",mLogcount,mLogWorking,mSendCount,mSocketWorking,queueSize,mInQueueIndex,mOutQueueIndex,e,retryWriteCount);
                goto RECONNECT ;
            }
            mSocketWorking=4;
            mLogElementQueue[mOutQueueIndex].pop_front();
            delete element;
            mOutQueueFreeCount++;
        }

        mSendCount++;

        int elptime= GetTime() - nowTime;
        float ss=-1;
        if(elptime>0) {
            if(queueSize>DATA_THRESHOLD) {
                ss=queueSize*1.0000001/1024/1024/(elptime*1.0000001/1000/1000);
            }
        }

        mSocketWorking=5;
        lockQueue();
        mSocketWorking=6;

        mSocketWorking=7;

        int tmpIndex=mInQueueIndex;
        mInQueueIndex=mOutQueueIndex;
        mOutQueueIndex=tmpIndex;

        mSocketWorking=8;
        queueSize=mInQueueSize;
        mInQueueSize=0;

        unlockQueue();
        mSocketWorking=9;
        if(queueSize<DATA_THRESHOLD) {
            usleep(SEND_PERIOD);
        }
    } while(true);
    return NULL;
}

void YLogBuffer:: init() {
    mInQueueSizeMax = property_get_bool("ro.config.low_ram",
                                        BOOL_DEFAULT_FALSE)
                      ? YLOG_BUFFER_MIN_SIZE
                      : YLOG_BUFFER_SIZE;

    pthread_attr_t attr;
    static  pthread_t threadid;
    if (!pthread_attr_init(&attr)) {
        if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
            if (!pthread_create(&threadid, &attr, YLogBuffer::BufferSender, 0)) {
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
