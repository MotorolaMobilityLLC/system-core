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

#include <sys/types.h>

#include <list>
#include <optional>
#include <string>

#include <android-base/thread_annotations.h>
#include <android/log.h>
#include <private/android_filesystem_config.h>

#include "LogBuffer.h"
#include "LogBufferElement.h"
#include "LogReaderList.h"
#include "LogReaderThread.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "LogWriter.h"
#include "LogdLock.h"
#include "PruneList.h"
#include "SimpleLogBuffer.h"

typedef std::list<LogBufferElement> LogBufferElementCollection;

class ChattyLogBuffer : public SimpleLogBuffer {
    // watermark of any worst/chatty uid processing
    typedef std::unordered_map<uid_t, LogBufferElementCollection::iterator> LogBufferIteratorMap;
    LogBufferIteratorMap mLastWorst[LOG_ID_MAX] GUARDED_BY(logd_lock);
    // watermark of any worst/chatty pid of system processing
    typedef std::unordered_map<pid_t, LogBufferElementCollection::iterator> LogBufferPidIteratorMap;
    LogBufferPidIteratorMap mLastWorstPidOfSystem[LOG_ID_MAX] GUARDED_BY(logd_lock);

  public:
    ChattyLogBuffer(LogReaderList* reader_list, LogTags* tags, PruneList* prune,
                    LogStatistics* stats);
    ~ChattyLogBuffer();

  protected:
    bool Prune(log_id_t id, unsigned long pruneRows, uid_t uid) REQUIRES(logd_lock) override;
    void LogInternal(LogBufferElement&& elem) REQUIRES(logd_lock) override;

  private:
    LogBufferElementCollection::iterator Erase(LogBufferElementCollection::iterator it,
                                               bool coalesce = false) REQUIRES(logd_lock);

    PruneList* prune_;

    // This always contains a copy of the last message logged, for deduplication.
    std::optional<LogBufferElement> last_logged_elements_[LOG_ID_MAX] GUARDED_BY(logd_lock);
    // This contains an element if duplicate messages are seen.
    // Its `dropped` count is `duplicates seen - 1`.
    std::optional<LogBufferElement> duplicate_elements_[LOG_ID_MAX] GUARDED_BY(logd_lock);
};
