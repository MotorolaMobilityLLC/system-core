/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "histogram_logger.h"

#include <cstdlib>

#include <android-base/logging.h>
#include <log/log.h>

namespace bootstat {

void LogHistogram(const std::string& event, int32_t data) {
  LOG(INFO) << "Logging histogram: " << event << " " << data;
  android_log_event_context log(HISTOGRAM_LOG_TAG);
  log << event << data << LOG_ID_EVENTS;
}

}  // namespace bootstat
