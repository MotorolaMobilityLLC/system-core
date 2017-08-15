/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "Log"

#include <utils/Log.h>
#include <utils/Timers.h>

namespace android {

LogIfSlow::LogIfSlow(
        const char* tag, android_LogPriority priority, int timeoutMillis, const char* message)
        : mTag(tag), mPriority(priority), mTimeoutMillis(timeoutMillis), mMessage(message),
          mStart(systemTime(SYSTEM_TIME_BOOTTIME)) {
}

LogIfSlow::~LogIfSlow() {
    int durationMillis = (int)nanoseconds_to_milliseconds(systemTime(SYSTEM_TIME_BOOTTIME) - mStart);
    if (durationMillis > mTimeoutMillis) {
        LOG_PRI(mPriority, mTag, "%s: %dms", mMessage, durationMillis);
    }
}

} // namespace android
