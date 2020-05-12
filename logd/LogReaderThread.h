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

#include <log/log.h>
#include <sysutils/SocketClient.h>

#include "LogBuffer.h"

class LogReader;
class LogBufferElement;
class LogReaderList;

class LogReaderThread {
  public:
    LogReaderThread(LogReader& reader, LogReaderList& reader_list, SocketClient* client,
                    bool non_block, unsigned long tail, unsigned int log_mask, pid_t pid,
                    log_time start_time, uint64_t sequence,
                    std::chrono::steady_clock::time_point deadline, bool privileged,
                    bool can_read_security_logs);

    bool startReader_Locked();

    void triggerReader_Locked() { thread_triggered_condition_.notify_all(); }

    void triggerSkip_Locked(log_id_t id, unsigned int skip) { skip_ahead_[id] = skip; }
    void cleanSkip_Locked();

    void release_Locked() {
        // gracefully shut down the socket.
        shutdown(client_->getSocket(), SHUT_RDWR);
        release_ = true;
        thread_triggered_condition_.notify_all();
    }

    bool IsWatching(log_id_t id) const { return log_mask_ & (1 << id); }
    bool IsWatchingMultiple(unsigned int log_mask) const { return log_mask_ & log_mask; }

    const SocketClient* client() const { return client_; }
    uint64_t start() const { return start_; }
    std::chrono::steady_clock::time_point deadline() const { return deadline_; }

  private:
    void ThreadFunction();
    // flushTo filter callbacks
    FlushToResult FilterFirstPass(const LogBufferElement* element);
    FlushToResult FilterSecondPass(const LogBufferElement* element);

    // Set to true to cause the thread to end and the LogReaderThread to delete itself.
    bool release_ = false;
    // Indicates whether or not 'leading' (first logs seen starting from start_) 'dropped' (chatty)
    // messages should be ignored.
    bool leading_dropped_;

    // Condition variable for waking the reader thread if there are messages pending for its client.
    std::condition_variable thread_triggered_condition_;

    // Reference to the parent thread that manages log reader sockets.
    LogReader& reader_;
    // Reference to the parent list that shares its lock with each instance
    LogReaderList& reader_list_;
    // A mask of the logs buffers that are read by this reader.
    const unsigned int log_mask_;
    // If set to non-zero, only pids equal to this are read by the reader.
    const pid_t pid_;
    // When a reader is referencing (via start_) old elements in the log buffer, and the log
    // buffer's size grows past its memory limit, the log buffer may request the reader to skip
    // ahead a specified number of logs.
    unsigned int skip_ahead_[LOG_ID_MAX];
    // Used for distinguishing 'dropped' messages for duplicate logs vs chatty drops
    pid_t last_tid_[LOG_ID_MAX];

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

    // A pointer to the socket for this reader.
    SocketClient* client_;
    // When a reader requests logs starting from a given timestamp, its stored here for the first
    // pass, such that logs before this time stamp that are accumulated in the buffer are ignored.
    log_time start_time_;
    // The point from which the reader will read logs once awoken.
    uint64_t start_;
    // CLOCK_MONOTONIC based deadline used for log wrapping.  If this deadline expires before logs
    // wrap, then wake up and send the logs to the reader anyway.
    std::chrono::steady_clock::time_point deadline_;
    // If this reader is 'dumpAndClose' and will disconnect once it has read its intended logs.
    const bool non_block_;

    // Whether or not this reader can read logs from all UIDs or only its own UID.  See
    // clientHasLogCredentials().
    bool privileged_;
    // Whether or not this reader can read security logs.  See CanReadSecurityLogs().
    bool can_read_security_logs_;
};
