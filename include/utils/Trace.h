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

#ifndef ANDROID_TRACE_H
#define ANDROID_TRACE_H

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cutils/compiler.h>
#include <utils/threads.h>
#include <cutils/trace.h>

// See <cutils/trace.h> for more ATRACE_* macros.

// ATRACE_CALL traces the beginning and end of the current function.  To trace
// the correct start and end times this macro should be the first line of the
// function body.
#define ATRACE_CALL() android::ScopedTrace ___tracer(ATRACE_TAG, __FUNCTION__)

// ATRACE_NAME traces the beginning and end of the current function.  To trace
// the correct start and end times this macro should be the first line of the
// function body.
#define ATRACE_NAME(name) android::ScopedTrace ___tracer(ATRACE_TAG, name)

namespace android {

class ScopedTrace {
public:
inline ScopedTrace(uint64_t tag, const char* name)
    : mTag(tag) {
    atrace_begin(mTag,name);
}

inline ~ScopedTrace() {
    atrace_end(mTag);
}

private:
    uint64_t mTag;
};

}; // namespace android

#endif // ANDROID_TRACE_H
