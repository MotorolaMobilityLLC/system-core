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

#include "LogReaderThread.h"

#include <errno.h>
#include <string.h>
#include <sys/prctl.h>

#include <thread>

#include "LogBuffer.h"
#include "LogReader.h"

using namespace std::placeholders;

LogReaderThread::LogReaderThread(LogReader& reader, LogReaderList& reader_list,
                                 SocketClient* client, bool non_block, unsigned long tail,
                                 unsigned int log_mask, pid_t pid, log_time start_time,
                                 uint64_t start, std::chrono::steady_clock::time_point deadline,
                                 bool privileged, bool can_read_security_logs)
    : leading_dropped_(false),
      reader_(reader),
      reader_list_(reader_list),
      log_mask_(log_mask),
      pid_(pid),
      tail_(tail),
      count_(0),
      index_(0),
      client_(client),
      start_time_(start_time),
      start_(start),
      deadline_(deadline),
      non_block_(non_block),
      privileged_(privileged),
      can_read_security_logs_(can_read_security_logs) {
    memset(last_tid_, 0, sizeof(last_tid_));
    cleanSkip_Locked();
}

bool LogReaderThread::startReader_Locked() {
    auto thread = std::thread{&LogReaderThread::ThreadFunction, this};
    thread.detach();
    return true;
}

void LogReaderThread::ThreadFunction() {
    prctl(PR_SET_NAME, "logd.reader.per");

    SocketClient* client = client_;

    LogBuffer& logbuf = *reader_.log_buffer();

    leading_dropped_ = true;

    auto lock = std::unique_lock{reader_list_.reader_threads_lock()};

    uint64_t start = start_;

    while (!release_) {
        if (deadline_.time_since_epoch().count() != 0) {
            if (thread_triggered_condition_.wait_until(lock, deadline_) ==
                std::cv_status::timeout) {
                deadline_ = {};
            }
            if (release_) {
                break;
            }
        }

        lock.unlock();

        if (tail_) {
            logbuf.flushTo(client, start, nullptr, privileged_, can_read_security_logs_,
                           std::bind(&LogReaderThread::FilterFirstPass, this, _1));
            leading_dropped_ =
                    true;  // TODO: Likely a bug, if leading_dropped_ was not true before calling
                           // flushTo(), then it should not be reset to true after.
        }
        start = logbuf.flushTo(client, start, last_tid_, privileged_, can_read_security_logs_,
                               std::bind(&LogReaderThread::FilterSecondPass, this, _1));

        // We only ignore entries before the original start time for the first flushTo(), if we
        // get entries after this first flush before the original start time, then the client
        // wouldn't have seen them.
        // Note: this is still racy and may skip out of order events that came in since the last
        // time the client disconnected and then reconnected with the new start time.  The long term
        // solution here is that clients must request events since a specific sequence number.
        start_time_.tv_sec = 0;
        start_time_.tv_nsec = 0;

        lock.lock();

        if (start == LogBufferElement::FLUSH_ERROR) {
            break;
        }

        start_ = start + 1;

        if (non_block_ || release_) {
            break;
        }

        cleanSkip_Locked();

        if (deadline_.time_since_epoch().count() == 0) {
            thread_triggered_condition_.wait(lock);
        }
    }

    reader_.release(client);
    client->decRef();

    auto& log_reader_threads = reader_list_.reader_threads();
    auto it = std::find_if(log_reader_threads.begin(), log_reader_threads.end(),
                           [this](const auto& other) { return other.get() == this; });

    if (it != log_reader_threads.end()) {
        log_reader_threads.erase(it);
    }
}

// A first pass to count the number of elements
FlushToResult LogReaderThread::FilterFirstPass(const LogBufferElement* element) {
    auto lock = std::lock_guard{reader_list_.reader_threads_lock()};

    if (leading_dropped_) {
        if (element->getDropped()) {
            return FlushToResult::kSkip;
        }
        leading_dropped_ = false;
    }

    if (count_ == 0) {
        start_ = element->getSequence();
    }

    if ((!pid_ || pid_ == element->getPid()) && IsWatching(element->getLogId()) &&
        (start_time_ == log_time::EPOCH || start_time_ <= element->getRealTime())) {
        ++count_;
    }

    return FlushToResult::kSkip;
}

// A second pass to send the selected elements
FlushToResult LogReaderThread::FilterSecondPass(const LogBufferElement* element) {
    auto lock = std::lock_guard{reader_list_.reader_threads_lock()};

    start_ = element->getSequence();

    if (skip_ahead_[element->getLogId()]) {
        skip_ahead_[element->getLogId()]--;
        return FlushToResult::kSkip;
    }

    if (leading_dropped_) {
        if (element->getDropped()) {
            return FlushToResult::kSkip;
        }
        leading_dropped_ = false;
    }

    // Truncate to close race between first and second pass
    if (non_block_ && tail_ && index_ >= count_) {
        return FlushToResult::kStop;
    }

    if (!IsWatching(element->getLogId())) {
        return FlushToResult::kSkip;
    }

    if (pid_ && pid_ != element->getPid()) {
        return FlushToResult::kSkip;
    }

    if (start_time_ != log_time::EPOCH && element->getRealTime() <= start_time_) {
        return FlushToResult::kSkip;
    }

    if (release_) {
        return FlushToResult::kStop;
    }

    if (!tail_) {
        goto ok;
    }

    ++index_;

    if (count_ > tail_ && index_ <= (count_ - tail_)) {
        return FlushToResult::kSkip;
    }

    if (!non_block_) {
        tail_ = 0;
    }

ok:
    if (!skip_ahead_[element->getLogId()]) {
        return FlushToResult::kWrite;
    }
    return FlushToResult::kSkip;
}

void LogReaderThread::cleanSkip_Locked(void) {
    memset(skip_ahead_, 0, sizeof(skip_ahead_));
}
