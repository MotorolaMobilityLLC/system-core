/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "thread_pool.h"
#include "uevent.h"

namespace android {
namespace init {

enum ThreadPoolPriority {
    // Kernel module loading should have the highest priority as they form a dependency chain and
    // sit on the critical path.
    kPriorityModalias = 0,
    // SELinux restorecon operations should have the second highest priority as they may be
    // time-consuming while they do not have dependencies.
    kPriorityRestorecon = 1,
    // The rest falls into the same priority.
    kPriorityDevice = 2,
    kPriorityFirmware = 2,
};

class UeventHandler {
  public:
    virtual ~UeventHandler() = default;

    virtual void HandleUevent(const Uevent& uevent) = 0;

    virtual void ColdbootDone() {}

    // Enqueue a uevent to the thread pool.
    virtual void EnqueueUevent(const Uevent& uevent, ThreadPool& thread_pool) = 0;
};

}  // namespace init
}  // namespace android
