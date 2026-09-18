/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include "coldboot_runner.h"

namespace android {
namespace init {

ColdbootRunnerThreadPool::ColdbootRunnerThreadPool(
        unsigned int num_threads, const std::vector<Uevent>& uevent_queue,
        const std::vector<std::shared_ptr<UeventHandler>>& uevent_handlers,
        bool enable_parallel_restorecon, const std::vector<std::string>& restorecon_queue)
    : uevent_queue_(uevent_queue),
      uevent_handlers_(uevent_handlers),
      enable_parallel_restorecon_(enable_parallel_restorecon),
      restorecon_queue_(restorecon_queue),
      thread_pool_(num_threads) {}

void ColdbootRunnerThreadPool::StartInBackground() {
    for (const auto& uevent_handler : uevent_handlers_) {
        for (const auto& uevent : uevent_queue_) {
            uevent_handler->EnqueueUevent(uevent, thread_pool_);
        }
    }
    if (enable_parallel_restorecon_) {
        for (const std::string& restorecon : restorecon_queue_) {
            thread_pool_.Enqueue(kPriorityRestorecon,
                                 [&restorecon] { RestoreconRecurse(restorecon); });
        }
    }
}

void ColdbootRunnerThreadPool::Wait() {
    thread_pool_.Wait();
}

}  // namespace init
}  // namespace android
