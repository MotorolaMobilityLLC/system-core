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

#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <log/log.h>
#include <sysutils/SocketClient.h>

class LogBuffer;

#define EXPIRE_HOUR_THRESHOLD 24  // Only expire chatty UID logs to preserve
                                  // non-chatty UIDs less than this age in hours
#define EXPIRE_THRESHOLD 10       // A smaller expire count is considered too
                                  // chatty for the temporal expire messages
#define EXPIRE_RATELIMIT 10  // maximum rate in seconds to report expiration

class __attribute__((packed)) LogBufferElement {
    friend LogBuffer;

    // sized to match reality of incoming log packets
    const uint32_t mUid;
    const uint32_t mPid;
    const uint32_t mTid;
    uint64_t mSequence;
    log_time mRealTime;
    union {
        char* mMsg;    // mDropped == false
        int32_t mTag;  // mDropped == true
    };
    union {
        const uint16_t mMsgLen;  // mDropped == false
        uint16_t mDroppedCount;  // mDropped == true
    };
    const uint8_t mLogId;
    bool mDropped;

    static atomic_int_fast64_t sequence;

    // assumption: mDropped == true
    size_t populateDroppedMessage(char*& buffer, LogBuffer* parent,
                                  bool lastSame);

   public:
    LogBufferElement(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid,
                     pid_t tid, const char* msg, uint16_t len);
    LogBufferElement(const LogBufferElement& elem);
    ~LogBufferElement();

    bool isBinary(void) const {
        return (mLogId == LOG_ID_EVENTS) || (mLogId == LOG_ID_SECURITY);
    }

    log_id_t getLogId() const {
        return static_cast<log_id_t>(mLogId);
    }
    uid_t getUid(void) const {
        return mUid;
    }
    pid_t getPid(void) const {
        return mPid;
    }
    pid_t getTid(void) const {
        return mTid;
    }
    uint32_t getTag() const;
    uint16_t getDropped(void) const {
        return mDropped ? mDroppedCount : 0;
    }
    uint16_t setDropped(uint16_t value);
    uint16_t getMsgLen() const {
        return mDropped ? 0 : mMsgLen;
    }
    const char* getMsg() const {
        return mDropped ? nullptr : mMsg;
    }
    uint64_t getSequence() const { return mSequence; }
    static uint64_t getCurrentSequence() { return sequence.load(memory_order_relaxed); }
    log_time getRealTime(void) const {
        return mRealTime;
    }

    static const uint64_t FLUSH_ERROR;
    uint64_t flushTo(SocketClient* writer, LogBuffer* parent, bool lastSame);
};
