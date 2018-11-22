/*
 * Copyright (C) 2014 The Android Open Source Project
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
#include <string.h>
#include <sys/prctl.h>

#include <private/android_logger.h>

#include "FlushCommand.h"
#include "LogBuffer.h"
#include "LogReader.h"
#include "LogTimes.h"

pthread_mutex_t LogTimeEntry::timesLock = PTHREAD_MUTEX_INITIALIZER;
#if defined(MTK_LOGD_ENHANCE) && defined(MTK_LOGD_FILTER)
pthread_mutex_t LogTimeEntry::readerCntLock = PTHREAD_MUTEX_INITIALIZER;
#endif

LogTimeEntry::LogTimeEntry(LogReader& reader, SocketClient* client,
                           bool nonBlock, unsigned long tail, log_mask_t logMask,
                           pid_t pid, log_time start, uint64_t timeout)
    : mRefCount(1),
      mRelease(false),
      mError(false),
      threadRunning(false),
      leadingDropped(false),
      mReader(reader),
      mLogMask(logMask),
      mPid(pid),
      mCount(0),
      mTail(tail),
      mIndex(0),
      mClient(client),
      mStart(start),
      mNonBlock(nonBlock),
      mEnd(log_time(android_log_clockid())) {
    mTimeout.tv_sec = timeout / NS_PER_SEC;
    mTimeout.tv_nsec = timeout % NS_PER_SEC;
    memset(mLastTid, 0, sizeof(mLastTid));
    pthread_cond_init(&threadTriggeredCondition, nullptr);
    cleanSkip_Locked();
}

void LogTimeEntry::startReader_Locked(void) {
    pthread_attr_t attr;

    threadRunning = true;

    if (!pthread_attr_init(&attr)) {
        if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
            if (!pthread_create(&mThread, &attr, LogTimeEntry::threadStart,
                                this)) {
                pthread_attr_destroy(&attr);
                return;
            }
        }
        pthread_attr_destroy(&attr);
    }
    threadRunning = false;
    if (mClient) {
        mClient->decRef();
    }
    decRef_Locked();
}

void LogTimeEntry::threadStop(void* obj) {
    LogTimeEntry* me = reinterpret_cast<LogTimeEntry*>(obj);

#ifdef MTK_LOGD_ENHANCE
#if defined(MTK_LOGD_FILTER)
    pthread_mutex_lock(&readerCntLock);
    logd_reader_del();
    pthread_mutex_unlock(&readerCntLock);
#else
    prdebug_ratelimit("logd.reader.per thread stop.\n");
#endif
#endif

    wrlock();

    if (me->mNonBlock) {
        me->error_Locked();
    }

    SocketClient* client = me->mClient;

    if (me->isError_Locked()) {
        LogReader& reader = me->mReader;
        LastLogTimes& times = reader.logbuf().mTimes;

        LastLogTimes::iterator it = times.begin();
        while (it != times.end()) {
            if (*it == me) {
                times.erase(it);
                me->release_nodelete_Locked();
                break;
            }
            it++;
        }

        me->mClient = nullptr;
        reader.release(client);
    }

    if (client) {
        client->decRef();
    }

    me->threadRunning = false;
    me->decRef_Locked();

    unlock();
}

void* LogTimeEntry::threadStart(void* obj) {
    prctl(PR_SET_NAME, "logd.reader.per");

    LogTimeEntry* me = reinterpret_cast<LogTimeEntry*>(obj);

    pthread_cleanup_push(threadStop, obj);

    SocketClient* client = me->mClient;
    if (!client) {
        me->error();
        return nullptr;
    }

    LogBuffer& logbuf = me->mReader.logbuf();

    bool privileged = FlushCommand::hasReadLogs(client);
    bool security = FlushCommand::hasSecurityLogs(client);

    me->leadingDropped = true;

#ifdef MTK_LOGD_ENHANCE
#if defined(MTK_LOGD_FILTER)
    pthread_mutex_lock(&readerCntLock);
    logd_reader_add();
    pthread_mutex_unlock(&readerCntLock);
#else
    prdebug_ratelimit("logd.reader.per thread start.\n");
#endif
#endif

    wrlock();

    log_time start = me->mStart;

    while (me->threadRunning && !me->isError_Locked()) {
        if (me->mTimeout.tv_sec || me->mTimeout.tv_nsec) {
            if (pthread_cond_timedwait(&me->threadTriggeredCondition,
                                       &timesLock, &me->mTimeout) == ETIMEDOUT) {
                me->mTimeout.tv_sec = 0;
                me->mTimeout.tv_nsec = 0;
            }
            if (!me->threadRunning || me->isError_Locked()) {
                break;
            }
        }

        unlock();

        if (me->mTail) {
            logbuf.flushTo(client, start, nullptr, privileged, security,
                           FilterFirstPass, me);
            me->leadingDropped = true;
        }
        start = logbuf.flushTo(client, start, me->mLastTid, privileged,
                               security, FilterSecondPass, me);

        wrlock();

        if (start == LogBufferElement::FLUSH_ERROR) {
            me->error_Locked();
            break;
        }

        me->mStart = start + log_time(0, 1);

        if (me->mNonBlock || !me->threadRunning || me->isError_Locked()) {
            break;
        }

        me->cleanSkip_Locked();

        if (!me->mTimeout.tv_sec && !me->mTimeout.tv_nsec) {
            pthread_cond_wait(&me->threadTriggeredCondition, &timesLock);
        }
    }

    unlock();

    pthread_cleanup_pop(true);

    return nullptr;
}

// A first pass to count the number of elements
int LogTimeEntry::FilterFirstPass(const LogBufferElement* element, void* obj) {
    LogTimeEntry* me = reinterpret_cast<LogTimeEntry*>(obj);

    LogTimeEntry::wrlock();

    if (me->leadingDropped) {
        if (element->getDropped()) {
            LogTimeEntry::unlock();
            return false;
        }
        me->leadingDropped = false;
    }

    if (me->mCount == 0) {
        me->mStart = element->getRealTime();
    }

    if ((!me->mPid || (me->mPid == element->getPid())) &&
        (me->isWatching(element->getLogId()))) {
        ++me->mCount;
    }

    LogTimeEntry::unlock();

    return false;
}

// A second pass to send the selected elements
int LogTimeEntry::FilterSecondPass(const LogBufferElement* element, void* obj) {
    LogTimeEntry* me = reinterpret_cast<LogTimeEntry*>(obj);

    LogTimeEntry::wrlock();

    me->mStart = element->getRealTime();

    if (me->skipAhead[element->getLogId()]) {
        me->skipAhead[element->getLogId()]--;
        goto skip;
    }

    if (me->leadingDropped) {
        if (element->getDropped()) {
            goto skip;
        }
        me->leadingDropped = false;
    }

    // Truncate to close race between first and second pass
    if (me->mNonBlock && me->mTail && (me->mIndex >= me->mCount)) {
        goto stop;
    }

    if (!me->isWatching(element->getLogId())) {
        goto skip;
    }

    if (me->mPid && (me->mPid != element->getPid())) {
        goto skip;
    }

    if (me->isError_Locked()) {
        goto stop;
    }

    if (!me->mTail) {
        goto ok;
    }

    ++me->mIndex;

    if ((me->mCount > me->mTail) && (me->mIndex <= (me->mCount - me->mTail))) {
        goto skip;
    }

    if (!me->mNonBlock) {
        me->mTail = 0;
    }

ok:
    if (!me->skipAhead[element->getLogId()]) {
        LogTimeEntry::unlock();
        return true;
    }
// FALLTHRU

skip:
    LogTimeEntry::unlock();
    return false;

stop:
    LogTimeEntry::unlock();
    return -1;
}

void LogTimeEntry::cleanSkip_Locked(void) {
    memset(skipAhead, 0, sizeof(skipAhead));
}
