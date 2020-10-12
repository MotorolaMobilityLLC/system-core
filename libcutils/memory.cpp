/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <cutils/memory.h>

#include <log/log.h>

#ifdef __BIONIC__
#include <bionic/malloc.h>
#endif

void process_disable_memory_mitigations() {
    bool success = false;
#ifdef __BIONIC__
    // TODO(b/158870657) is fixed and scudo is used globally, we can assert when an
    // an error is returned.

    success = android_mallopt(M_DISABLE_MEMORY_MITIGATIONS, nullptr, 0);
#endif

    if (success) {
        ALOGI("Disabled memory mitigations for process.");
    } else {
        ALOGE("Could not disable memory mitigations for process.");
    }
}
