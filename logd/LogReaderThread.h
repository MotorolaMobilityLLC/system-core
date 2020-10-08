/*
 * Copyright (C) 2012-2013 The Android Open Source Project
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

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <chrono>
#include <condition_variable>
#include <list>
#include <memory>

#include <android-base/thread_annotations.h>
#include <log/log.h>

#include "LogBuffer.h"
#include "LogWriter.h"
#include "LogdLock.h"

class LogReaderList;

class LogReaderThread {
  public:
    LogReaderThread(LogBuffer* log_buffer, LogReaderList* reader_list,
                    std::unique_ptr<LogWriter> writer, bool non_block, unsigned long tail,
                    LogMask log_mask, pid_t pid, log_time start_time, uint64_t sequence,
                    std::chrono::steady_clock::time_point deadline);
    void TriggerReader() REQUIRES(logd_lock) { thread_triggered_condition_.notify_all(); }

    void TriggerSkip(log_id_t id, unsigned int skip) REQUIRES(logd_lock) { skip_ahead_[id] = skip; }
    void CleanSkip() REQUIRES(logd_lock) { memset(skip_ahead_, 0, sizeof(skip_ahead_)); }

    void Release() REQUIRES(logd_lock) {
        // gracefully shut down the socket.
        writer_->Shutdown();
        release_ = true;
        thread_triggered_condition_.notify_all();
    }

    bool IsWatching(log_id_t id) const REQUIRES(logd_lock) {
        return flush_to_state_->log_mask() & (1 << id);
    }
    bool IsWatchingMultiple(LogMask log_mask) const REQUIRES(logd_lock) {
        return flush_to_state_->log_mask() & log_mask;
    }

    std::string name() const REQUIRES(logd_lock) { return writer_->name(); }
    uint64_t start() const REQUIRES(logd_lock) { return flush_to_state_->start(); }
    std::chrono::steady_clock::time_point deadline() const REQUIRES(logd_lock) { return deadline_; }
    FlushToState& flush_to_state() REQUIRES(logd_lock) { return *flush_to_state_; }

  private:
    void ThreadFunction();
    // flushTo filter callbacks
    FilterResult FilterFirstPass(log_id_t log_id, pid_t pid, uint64_t sequence, log_time realtime)
            REQUIRES(logd_lock);
    FilterResult FilterSecondPass(log_id_t log_id, pid_t pid, uint64_t sequence, log_time realtime)
            REQUIRES(logd_lock);

    std::condition_variable thread_triggered_condition_;
    LogBuffer* log_buffer_;
    LogReaderList* reader_list_;
    std::unique_ptr<LogWriter> writer_ GUARDED_BY(logd_lock);

    // Set to true to cause the thread to end and the LogReaderThread to delete itself.
    bool release_ GUARDED_BY(logd_lock) = false;

    // If set to non-zero, only pids equal to this are read by the reader.
    const pid_t pid_;
    // When a reader is referencing (via start_) old elements in the log buffer, and the log
    // buffer's size grows past its memory limit, the log buffer may request the reader to skip
    // ahead a specified number of logs.
    unsigned int skip_ahead_[LOG_ID_MAX] GUARDED_BY(logd_lock);
    // LogBuffer::FlushTo() needs to store state across subsequent calls.
    std::unique_ptr<FlushToState> flush_to_state_ GUARDED_BY(logd_lock);

    // These next three variables are used for reading only the most recent lines aka `adb logcat
    // -t` / `adb logcat -T`.
    // tail_ is the number of most recent lines to print.
    unsigned long tail_;
    // count_ is the result of a first pass through the log buffer to determine how many total
    // messages there are.
    unsigned long count_;
    // index_ is used along with count_ to only start sending lines once index_ > (count_ - tail_)
    // and to disconnect the reader (if it is dumpAndClose, `adb logcat -t`), when index_ >= count_.
    unsigned long index_;

    // When a reader requests logs starting from a given timestamp, its stored here for the first
    // pass, such that logs before this time stamp that are accumulated in the buffer are ignored.
    log_time start_time_;
    // CLOCK_MONOTONIC based deadline used for log wrapping.  If this deadline expires before logs
    // wrap, then wake up and send the logs to the reader anyway.
    std::chrono::steady_clock::time_point deadline_ GUARDED_BY(logd_lock);
    // If this reader is 'dumpAndClose' and will disconnect once it has read its intended logs.
    const bool non_block_;
};
