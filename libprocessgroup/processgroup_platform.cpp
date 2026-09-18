/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <processgroup/processgroup_platform.h>

#include <signal.h>

#include <com_android_core_libprocessgroup_flags.h>
#include "internal.h"

namespace libprocessgroup_platform {

bool killProcessGroup(uid_t uid, pid_t pid) {
    using com::android::core::libprocessgroup::flags::reclaim_memcg_before_removal;
    return KillProcessGroup(uid, pid, SIGKILL, reclaim_memcg_before_removal()) == 0;
}

} // namespace libprocessgroup_platform
