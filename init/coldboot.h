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

#pragma once

#include <memory>
#include <set>
#include <thread>
#include <vector>

#include "uevent_handler.h"
#include "uevent_listener.h"

namespace android {
namespace init {

class ColdBoot {
  public:
    ColdBoot(UeventListener& uevent_listener,
             std::vector<std::shared_ptr<UeventHandler>>& uevent_handlers,
             bool enable_parallel_restorecon, std::vector<std::string> parallel_restorecon_queue)
        : uevent_listener_(uevent_listener),
          uevent_handlers_(uevent_handlers),
          enable_parallel_restorecon_(enable_parallel_restorecon),
          parallel_restorecon_queue_(parallel_restorecon_queue) {}

    void Run();

  private:
    void RegenerateUevents();
    void GenerateRestoreCon(const std::string& directory);

    UeventListener& uevent_listener_;
    std::vector<std::shared_ptr<UeventHandler>>& uevent_handlers_;

    bool enable_parallel_restorecon_;

    std::vector<Uevent> uevent_queue_;

    std::vector<std::string> restorecon_queue_;

    std::vector<std::string> parallel_restorecon_queue_;
};

}  // namespace init
}  // namespace android
