/*
 * Copyright 2026, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <sys/types.h>


/*
 * This header exposes APIs that have absolutely no stability guarantees of any kind.
 *
 * Do not attempt to use these APIs from any code that is updated independently of the system image
 * where this library is provided.
 */

namespace libprocessgroup_platform {

/**
 * @brief Sends SIGKILL to pid's processgroup, as well as all processes in its per-PID cgroup.
 * Waits for all processes to die, then optionally reclaims all memory from the PID memcg (based on
 * the value of com.android.core.libprocessgroup.flags.reclaim_memcg_before_removal) and then
 * removes the PID cgroup.
 *
 * @param uid The user ID of the process (group and cgroup) being killed / removed.
 * @param pid The process ID of the process (group and cgroup) being killed / removed.
 *
 * @return True if cgroup removal succeeded. False upon error.
 */
bool killProcessGroup(uid_t uid, pid_t pid);

} // namespace libprocessgroup_platform