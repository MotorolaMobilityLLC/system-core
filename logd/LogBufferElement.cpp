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

#include "LogBufferElement.h"

#include <ctype.h>
#include <endian.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <log/log_read.h>
#include <private/android_logger.h>

#include "LogStatistics.h"
#include "LogUtils.h"

LogBufferElement::LogBufferElement(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid,
                                   pid_t tid, uint64_t sequence, const char* msg, uint16_t len)
    : mUid(uid),
      mPid(pid),
      mTid(tid),
      mSequence(sequence),
      mRealTime(realtime),
      mMsgLen(len),
      mLogId(log_id),
      mDropped(false) {
    mMsg = new char[len];
    memcpy(mMsg, msg, len);
}

LogBufferElement::LogBufferElement(const LogBufferElement& elem)
    : mUid(elem.mUid),
      mPid(elem.mPid),
      mTid(elem.mTid),
      mSequence(elem.mSequence),
      mRealTime(elem.mRealTime),
      mMsgLen(elem.mMsgLen),
      mLogId(elem.mLogId),
      mDropped(elem.mDropped) {
    if (mDropped) {
        mTag = elem.getTag();
    } else {
        mMsg = new char[mMsgLen];
        memcpy(mMsg, elem.mMsg, mMsgLen);
    }
}

LogBufferElement::LogBufferElement(LogBufferElement&& elem)
    : mUid(elem.mUid),
      mPid(elem.mPid),
      mTid(elem.mTid),
      mSequence(elem.mSequence),
      mRealTime(elem.mRealTime),
      mMsgLen(elem.mMsgLen),
      mLogId(elem.mLogId),
      mDropped(elem.mDropped) {
    if (mDropped) {
        mTag = elem.getTag();
    } else {
        mMsg = elem.mMsg;
        elem.mMsg = nullptr;
    }
}

LogBufferElement::~LogBufferElement() {
    if (!mDropped) {
        delete[] mMsg;
    }
}

uint32_t LogBufferElement::getTag() const {
    // Binary buffers have no tag.
    if (!isBinary()) {
        return 0;
    }

    // Dropped messages store the tag in place of mMsg.
    if (mDropped) {
        return mTag;
    }

    // For non-dropped messages, we get the tag from the message header itself.
    if (mMsgLen < sizeof(android_event_header_t)) {
        return 0;
    }

    return reinterpret_cast<const android_event_header_t*>(mMsg)->tag;
}

uint16_t LogBufferElement::setDropped(uint16_t value) {
    if (mDropped) {
        return mDroppedCount = value;
    }

    // The tag information is saved in mMsg data, which is in a union with mTag, used after mDropped
    // is set to true. Therefore we save the tag value aside, delete mMsg, then set mTag to the tag
    // value in its place.
    auto old_tag = getTag();
    delete[] mMsg;
    mMsg = nullptr;

    mTag = old_tag;
    mDropped = true;
    return mDroppedCount = value;
}

// caller must own and free character string
char* android::tidToName(pid_t tid) {
    char* retval = nullptr;
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "/proc/%u/comm", tid);
    int fd = open(buffer, O_RDONLY);
    if (fd >= 0) {
        ssize_t ret = read(fd, buffer, sizeof(buffer));
        if (ret >= (ssize_t)sizeof(buffer)) {
            ret = sizeof(buffer) - 1;
        }
        while ((ret > 0) && isspace(buffer[ret - 1])) {
            --ret;
        }
        if (ret > 0) {
            buffer[ret] = '\0';
            retval = strdup(buffer);
        }
        close(fd);
    }

    // if nothing for comm, check out cmdline
    char* name = android::pidToName(tid);
    if (!retval) {
        retval = name;
        name = nullptr;
    }

    // check if comm is truncated, see if cmdline has full representation
    if (name) {
        // impossible for retval to be NULL if name not NULL
        size_t retval_len = strlen(retval);
        size_t name_len = strlen(name);
        // KISS: ToDo: Only checks prefix truncated, not suffix, or both
        if ((retval_len < name_len) &&
            !fastcmp<strcmp>(retval, name + name_len - retval_len)) {
            free(retval);
            retval = name;
        } else {
            free(name);
        }
    }
    return retval;
}

// assumption: mMsg == NULL
size_t LogBufferElement::populateDroppedMessage(char*& buffer, LogStatistics* stats,
                                                bool lastSame) {
    static const char tag[] = "chatty";

    if (!__android_log_is_loggable_len(ANDROID_LOG_INFO, tag, strlen(tag),
                                       ANDROID_LOG_VERBOSE)) {
        return 0;
    }

    static const char format_uid[] = "uid=%u%s%s %s %u line%s";
    const char* name = stats->UidToName(mUid);
    const char* commName = android::tidToName(mTid);
    if (!commName && (mTid != mPid)) {
        commName = android::tidToName(mPid);
    }
    if (!commName) {
        commName = stats->PidToName(mPid);
    }
    if (name && name[0] && commName && (name[0] == commName[0])) {
        size_t len = strlen(name + 1);
        if (!strncmp(name + 1, commName + 1, len)) {
            if (commName[len + 1] == '\0') {
                free(const_cast<char*>(commName));
                commName = nullptr;
            } else {
                free(const_cast<char*>(name));
                name = nullptr;
            }
        }
    }
    if (name) {
        char* buf = nullptr;
        int result = asprintf(&buf, "(%s)", name);
        if (result != -1) {
            free(const_cast<char*>(name));
            name = buf;
        }
    }
    if (commName) {
        char* buf = nullptr;
        int result = asprintf(&buf, " %s", commName);
        if (result != -1) {
            free(const_cast<char*>(commName));
            commName = buf;
        }
    }
    // identical to below to calculate the buffer size required
    const char* type = lastSame ? "identical" : "expire";
    size_t len = snprintf(nullptr, 0, format_uid, mUid, name ? name : "",
                          commName ? commName : "", type, getDropped(),
                          (getDropped() > 1) ? "s" : "");

    size_t hdrLen;
    if (isBinary()) {
        hdrLen = sizeof(android_log_event_string_t);
    } else {
        hdrLen = 1 + sizeof(tag);
    }

    buffer = static_cast<char*>(calloc(1, hdrLen + len + 1));
    if (!buffer) {
        free(const_cast<char*>(name));
        free(const_cast<char*>(commName));
        return 0;
    }

    size_t retval = hdrLen + len;
    if (isBinary()) {
        android_log_event_string_t* event =
            reinterpret_cast<android_log_event_string_t*>(buffer);

        event->header.tag = htole32(CHATTY_LOG_TAG);
        event->type = EVENT_TYPE_STRING;
        event->length = htole32(len);
    } else {
        ++retval;
        buffer[0] = ANDROID_LOG_INFO;
        strcpy(buffer + 1, tag);
    }

    snprintf(buffer + hdrLen, len + 1, format_uid, mUid, name ? name : "",
             commName ? commName : "", type, getDropped(),
             (getDropped() > 1) ? "s" : "");
    free(const_cast<char*>(name));
    free(const_cast<char*>(commName));

    return retval;
}

bool LogBufferElement::FlushTo(LogWriter* writer, LogStatistics* stats, bool lastSame) {
    struct logger_entry entry = {};

    entry.hdr_size = sizeof(struct logger_entry);
    entry.lid = mLogId;
    entry.pid = mPid;
    entry.tid = mTid;
    entry.uid = mUid;
    entry.sec = mRealTime.tv_sec;
    entry.nsec = mRealTime.tv_nsec;

    char* buffer = nullptr;
    const char* msg;
    if (mDropped) {
        entry.len = populateDroppedMessage(buffer, stats, lastSame);
        if (!entry.len) return true;
        msg = buffer;
    } else {
        msg = mMsg;
        entry.len = mMsgLen;
    }

    bool retval = writer->Write(entry, msg);

    if (buffer) free(buffer);

    return retval;
}
